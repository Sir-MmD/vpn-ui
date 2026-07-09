package service

import (
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mhsanaei/3x-ui/v2/backend"
	"github.com/mhsanaei/3x-ui/v2/logger"
)

// daemonBin resolves a bundled daemon (preferred) or a host binary from PATH.
func daemonBin(name string) string {
	if p := backend.DaemonPath(name); p != "" {
		return p
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return name
}

// pppdEnv returns the environment a pppd-based daemon (xl2tpd/pptpd) needs so
// OpenSSL finds the bundled legacy provider for MS-CHAP/MPPE. Empty for a system
// pppd (whose OpenSSL providers differ and must not be overridden).
func pppdEnv() []string {
	if backend.UsingBundledPppd() {
		return []string{"OPENSSL_MODULES=" + backend.OpenSSLModules}
	}
	return nil
}

// pptpdArgs returns pptpd's launch args: foreground, plus the bundled pppd when
// the bundle is in use.
func pptpdArgs() []string {
	args := []string{"--fg"}
	if backend.UsingBundledPppd() {
		args = append(args, "--ppp", backend.PppdBundled)
	}
	return args
}

// linkPptpCtrl ensures pptpd can exec the bundled pptpctrl from its compiled
// path. Previously done while writing the systemd unit; still required now that
// pptpd runs as a child process.
func linkPptpCtrl() {
	if err := backend.LinkPptpCtrl(); err != nil {
		logger.Warning("PPTP: failed to link pptpctrl:", err)
	}
}

// procmgr supervises the bundled VPN daemons (openvpn, xl2tpd, pptpd) as child
// processes of the panel binary instead of systemd services. Each managed
// process:
//   - captures stdout+stderr into a bounded ring buffer for the "Logs" viewer,
//   - is auto-restarted if it exits unexpectedly (mirrors systemd Restart=on-failure),
//   - dies with the panel (StopAll on shutdown), and its whole process group is
//     signalled so pppd children spawned by xl2tpd/pptpd are reaped too.

const procLogMaxLines = 800

// procLog is a bounded in-memory ring buffer of a daemon's recent output.
type procLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *procLog) Write(p []byte) (int, error) {
	// Stamp each captured line so the Logs viewer shows when output arrived
	// (daemon stdout/stderr has no timestamp of its own). Matches the panel
	// logger's time format for consistency across cores.
	ts := time.Now().Format("2006/01/02 15:04:05")
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, ln := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		if ln == "" {
			continue
		}
		l.lines = append(l.lines, ts+" "+ln)
	}
	if over := len(l.lines) - procLogMaxLines; over > 0 {
		l.lines = l.lines[over:]
	}
	return len(p), nil
}

func (l *procLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

func (l *procLog) add(line string) { _, _ = l.Write([]byte(line + "\n")) }

// managedProc is one supervised child daemon.
type managedProc struct {
	name string
	log  *procLog

	mu      sync.Mutex
	bin     string
	args    []string
	env     []string
	dir     string
	cmd     *exec.Cmd
	stopped bool // Stop() called → suppress auto-restart
	gen     int  // bumped on every (re)start/stop; supervisors compare against it
}

// ProcManager supervises the bundled VPN daemons as child processes.
type ProcManager struct {
	mu    sync.Mutex
	procs map[string]*managedProc
}

var procMgr = &ProcManager{procs: map[string]*managedProc{}}

// GetProcManager returns the shared process manager.
func GetProcManager() *ProcManager { return procMgr }

func (m *ProcManager) get(name string) *managedProc {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.procs[name]
}

// Start (re)launches the named daemon with the given command, replacing any
// running instance. Output is captured to the daemon's log ring buffer.
func (m *ProcManager) Start(name, bin string, args, env []string, dir string) error {
	m.mu.Lock()
	p := m.procs[name]
	if p == nil {
		p = &managedProc{name: name, log: &procLog{}}
		m.procs[name] = p
	}
	m.mu.Unlock()

	p.mu.Lock()
	defer p.mu.Unlock()
	// Supersede any current instance/supervisor and stop it.
	p.gen++
	p.terminateLocked()
	p.bin, p.args, p.env, p.dir = bin, args, env, dir
	p.stopped = false
	return p.launchLocked()
}

// launchLocked spawns the process and its supervisor goroutine (p.mu held).
func (p *managedProc) launchLocked() error {
	cmd := exec.Command(p.bin, p.args...)
	cmd.Dir = p.dir
	if len(p.env) > 0 {
		cmd.Env = append(os.Environ(), p.env...)
	}
	cmd.Stdout = p.log
	cmd.Stderr = p.log
	// Own process group so we can signal pppd/helper children too.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		p.log.add("[procmgr] failed to start " + p.bin + ": " + err.Error())
		return err
	}
	p.cmd = cmd
	p.log.add("[procmgr] started: " + p.bin + " " + strings.Join(p.args, " "))
	gen := p.gen
	go p.supervise(cmd, gen)
	return nil
}

// supervise waits for the process; if it exits without an explicit Stop and is
// still the current generation, it is restarted after a short delay.
func (p *managedProc) supervise(cmd *exec.Cmd, gen int) {
	waitErr := cmd.Wait()

	p.mu.Lock()
	defer p.mu.Unlock()
	if gen != p.gen || p.stopped {
		return // superseded or intentionally stopped
	}
	msg := "exited cleanly"
	if waitErr != nil {
		msg = "exited: " + waitErr.Error()
	}
	logger.Warningf("procmgr: %s %s — restarting in 5s", p.name, msg)
	p.log.add("[procmgr] " + msg + " — restarting in 5s")
	restartGen := p.gen
	go func() {
		time.Sleep(5 * time.Second)
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.stopped || p.gen != restartGen {
			return
		}
		p.gen++
		_ = p.launchLocked()
	}()
}

// terminateLocked signals the current process group with SIGTERM (p.mu held).
func (p *managedProc) terminateLocked() {
	if p.cmd == nil || p.cmd.Process == nil {
		return
	}
	pid := p.cmd.Process.Pid
	// Negative pid → whole process group (reaps pppd children). Fall back to the
	// bare process if the group signal fails.
	if err := syscall.Kill(-pid, syscall.SIGTERM); err != nil {
		_ = p.cmd.Process.Signal(syscall.SIGTERM)
	}
}

// Stop terminates the named daemon and disables auto-restart.
func (m *ProcManager) Stop(name string) error {
	p := m.get(name)
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopped = true
	p.gen++
	p.terminateLocked()
	return nil
}

// StopByPrefix stops every managed daemon whose name starts with prefix
// (e.g. "openvpn-server-" for all OpenVPN instances).
func (m *ProcManager) StopByPrefix(prefix string) {
	for _, name := range m.namesWithPrefix(prefix) {
		_ = m.Stop(name)
	}
}

func (m *ProcManager) namesWithPrefix(prefix string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var names []string
	for n := range m.procs {
		if strings.HasPrefix(n, prefix) {
			names = append(names, n)
		}
	}
	return names
}

// IsRunning reports whether the named daemon is currently up.
func (m *ProcManager) IsRunning(name string) bool {
	p := m.get(name)
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.stopped && p.cmd != nil && p.cmd.Process != nil && p.cmd.ProcessState == nil
}

// AnyRunningWithPrefix reports whether any managed daemon with the given name
// prefix is up (e.g. any OpenVPN transport for an inbound).
func (m *ProcManager) AnyRunningWithPrefix(prefix string) bool {
	for _, n := range m.namesWithPrefix(prefix) {
		if m.IsRunning(n) {
			return true
		}
	}
	return false
}

// Logs returns the captured output of the named daemon (most recent lines).
func (m *ProcManager) Logs(name string) string {
	p := m.get(name)
	if p == nil {
		return ""
	}
	return p.log.String()
}

// LogsByPrefix concatenates the logs of all daemons matching the prefix, each
// section headed by its name. Used for cores that run several processes
// (OpenVPN: one per inbound/transport).
func (m *ProcManager) LogsByPrefix(prefix string) string {
	names := m.namesWithPrefix(prefix)
	if len(names) == 0 {
		return ""
	}
	var b strings.Builder
	for i, n := range names {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString("===== " + n + " =====\n")
		b.WriteString(m.Logs(n))
		b.WriteString("\n")
	}
	return b.String()
}

// alive reports whether the named process is actually still running (ignoring
// the stopped flag).
func (m *ProcManager) alive(name string) bool {
	p := m.get(name)
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cmd != nil && p.cmd.Process != nil && p.cmd.ProcessState == nil
}

// kill SIGKILLs the named process group (last resort for a straggler).
func (m *ProcManager) kill(name string) {
	p := m.get(name)
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd != nil && p.cmd.Process != nil {
		pid := p.cmd.Process.Pid
		if syscall.Kill(-pid, syscall.SIGKILL) != nil {
			_ = p.cmd.Process.Kill()
		}
	}
}

// StopAll terminates every managed daemon and waits for them to exit (panel
// shutdown). Daemons that don't exit within the grace period are SIGKILLed, so
// nothing is left holding a port for the next panel start.
func (m *ProcManager) StopAll() {
	m.mu.Lock()
	names := make([]string, 0, len(m.procs))
	for n := range m.procs {
		names = append(names, n)
	}
	m.mu.Unlock()

	for _, n := range names {
		_ = m.Stop(n) // SIGTERM
	}
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		anyAlive := false
		for _, n := range names {
			if m.alive(n) {
				anyAlive = true
				break
			}
		}
		if !anyAlive {
			return
		}
		time.Sleep(150 * time.Millisecond)
	}
	for _, n := range names {
		if m.alive(n) {
			m.kill(n)
		}
	}
}

// migrateFromSystemdOnce tears down the previous systemd-based design (bundled
// units + running instances) so the panel can own the daemons as child
// processes. Idempotent and safe to call every startup: once the units are gone
// it is a no-op.
var migrateOnce sync.Once

func migrateFromSystemd() {
	migrateOnce.Do(func() {
		if !commandExists("systemctl") {
			return
		}
		// Stop + disable OpenVPN per-inbound instances.
		out, _ := exec.Command("systemctl", "list-units", "--all", "--no-legend", "openvpn-server@*").Output()
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(strings.TrimLeft(line, "●* "))
			if len(fields) > 0 && strings.HasPrefix(fields[0], "openvpn-server@") {
				_ = exec.Command("systemctl", "disable", "--now", fields[0]).Run()
			}
		}
		// Stop + disable the single-instance daemons.
		for _, unit := range []string{"xl2tpd", "pptpd"} {
			_ = exec.Command("systemctl", "disable", "--now", unit).Run()
		}
		// When we run our own bundled pluto, the host ipsec.service must not also be
		// running — it would hold UDP 500/4500 and conflict with the bundled daemon.
		if usingBundledIpsec() {
			_ = exec.Command("systemctl", "disable", "--now", "ipsec").Run()
		}
		// Remove the unit files the old design generated.
		for _, f := range []string{
			"/etc/systemd/system/openvpn-server@.service",
			"/etc/systemd/system/xl2tpd.service",
			"/etc/systemd/system/pptpd.service",
		} {
			_ = os.Remove(f)
		}
		_ = exec.Command("systemctl", "daemon-reload").Run()
		logger.Info("procmgr: migrated VPN daemons off systemd (now child processes)")

		// Kill orphaned bundled daemons left by a previous panel that was killed
		// without a clean shutdown (SIGKILL/crash) — they would hold the ports the
		// child processes need. Safe: procMgr has spawned nothing yet at this
		// point, so only pre-existing processes match.
		if commandExists("pkill") {
			for _, d := range []string{"openvpn", "xl2tpd", "pptpd"} {
				bin := daemonBin(d)
				if bin == d {
					continue // unresolved — avoid a too-broad match on a bare name
				}
				_ = exec.Command("pkill", "-KILL", "-f", bin).Run()
			}
			// Orphaned bundled pluto from a crashed panel (holds UDP 500/4500).
			if usingBundledIpsec() {
				_ = exec.Command("pkill", "-KILL", "-f", backend.LibreswanBundleRoot+"/libexec/ipsec/pluto.bin").Run()
			}
		}
	})
}
