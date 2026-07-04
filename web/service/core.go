package service

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v2/backend"
	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/logger"
)

// vpnKernelModules are the kernel modules the L2TP/PPTP/OpenVPN backends need.
// These are host/kernel-space and cannot be bundled into the binary — the
// setup/provision step ensures they are loaded and persisted.
var vpnKernelModules = []string{
	"ppp_generic",       // PPP core
	"l2tp_ppp",          // L2TP
	"nf_conntrack_pptp", // PPTP
	"ip_gre",            // PPTP/GRE
	"ppp_mppe",          // MPPE
	"nf_tproxy_ipv4",    // TPROXY (L2TP/PPTP/OpenVPN -> Xray)
	"af_key",            // IPsec
	"tun",               // OpenVPN tun device
}

// CoreState is the coarse health of a backend "core".
type CoreState string

const (
	CoreRunning      CoreState = "running"       // daemon is up
	CoreStopped      CoreState = "stopped"       // installed + has inbounds, but not running
	CoreIdle         CoreState = "idle"          // installed but no inbounds configured
	CoreNotInstalled CoreState = "not_installed" // binary missing (needs setup/bundle)
	CoreError        CoreState = "error"         // running attempt failed
)

// CoreStatus is the status of a single backend core shown in the Core Settings panel.
type CoreStatus struct {
	Name     string         `json:"name"`     // xray | l2tp | pptp | openvpn | radius
	State    CoreState      `json:"state"`    //
	Detail   string         `json:"detail"`   // human-readable extra info / error
	Version  string         `json:"version"`  // where available (xray)
	Inbounds int            `json:"inbounds"` // number of inbounds of this type
	Extra    map[string]any `json:"extra,omitempty"`
}

// ModuleStatus reports whether a required kernel module is loaded.
type ModuleStatus struct {
	Name   string `json:"name"`
	Loaded bool   `json:"loaded"`
}

// SystemStatus reports the host/kernel prerequisites that can't be baked into
// the binary — exactly the things the setup script used to worry about.
type SystemStatus struct {
	IpForward bool           `json:"ipForward"`
	Nftables  bool           `json:"nftables"`
	Iproute   bool           `json:"iproute"`
	Modules   []ModuleStatus `json:"modules"`
	ModulesOK bool           `json:"modulesOk"`
}

// ProvisionStep is one action taken by Provision(), for reporting to the UI/CLI.
// Warn marks a step that succeeded but needs the operator's attention (e.g. a
// kernel package was installed but its modules only load after a reboot). Log
// holds the raw command output for that step (package-manager output, modprobe
// errors, …), shown when the operator expands the step in the setup console.
type ProvisionStep struct {
	Name string `json:"name"`
	OK   bool   `json:"ok"`
	Warn bool   `json:"warn,omitempty"`
	Msg  string `json:"msg"`
	Log  string `json:"log,omitempty"`
}

// CoreService aggregates status and provisioning across all backend cores.
// Like the other services it is a zero-value-usable value type; its methods are
// stateless (they read the DB and probe the host), so a fresh copy works.
type CoreService struct {
	l2tpService    L2tpService
	pptpService    PptpService
	openvpnService OpenVpnService
	xrayService    XrayService
}

// --------------------------------------------------------------------------- //
//  Host probes
// --------------------------------------------------------------------------- //

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// daemonInstalled reports whether a daemon is available either from the host
// (in PATH) or from the bundle baked into the binary and extracted at setup.
func daemonInstalled(name string) bool {
	return commandExists(name) || backend.DaemonPath(name) != ""
}

func systemctlActive(unit string) bool {
	if !commandExists("systemctl") {
		return false
	}
	out, _ := exec.Command("systemctl", "is-active", unit).Output()
	return strings.TrimSpace(string(out)) == "active"
}

func moduleLoaded(name string) bool {
	// /sys/module/<name> exists for both loadable-and-loaded and built-in modules.
	_, err := os.Stat("/sys/module/" + name)
	return err == nil
}

// moduleAvailable reports whether a module can be used on the running kernel —
// already loaded, built into the kernel, or loadable on demand. It drives the
// "do we need to install a kernel package?" decision, so it must NOT false-
// negative on built-in modules (which have no /sys/module entry): `modprobe -nq`
// resolves both loadable .ko files and built-ins, returning success for either.
func moduleAvailable(name string) bool {
	if moduleLoaded(name) {
		return true
	}
	return exec.Command("modprobe", "-nq", name).Run() == nil
}

var (
	daemonVersionRe    = regexp.MustCompile(`\d+\.\d+(?:\.\d+)?`)
	daemonVersionCache = map[string]string{}
	daemonVersionMu    sync.Mutex
)

// daemonVersion returns a short version string (e.g. "2.6.12") for a bundled or
// host daemon by running `<bin> --version` and grabbing the first version-shaped
// token. Output is read regardless of exit code (some daemons exit non-zero on
// --version). Successful lookups are cached; "" is returned (and not cached) when
// the daemon isn't available, so it retries once it's installed.
func daemonVersion(name string) string {
	daemonVersionMu.Lock()
	if v, ok := daemonVersionCache[name]; ok {
		daemonVersionMu.Unlock()
		return v
	}
	daemonVersionMu.Unlock()

	bin := ""
	if p := backend.DaemonPath(name); p != "" {
		bin = p
	} else if p, err := exec.LookPath(name); err == nil {
		bin = p
	} else {
		return ""
	}
	out, _ := exec.Command(bin, "--version").CombinedOutput()
	v := daemonVersionRe.FindString(string(out))
	if v != "" {
		daemonVersionMu.Lock()
		daemonVersionCache[name] = v
		daemonVersionMu.Unlock()
	}
	return v
}

func procFileIsOne(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == "1"
}

// --------------------------------------------------------------------------- //
//  Per-core status
// --------------------------------------------------------------------------- //

// dokodemoPortBound reports whether something is already listening on the given
// TCP port — i.e. Xray bound its dokodemo-door for a VPN inbound. Probes by
// trying to bind: bind fails (address in use) → taken; bind succeeds → the port
// is free, meaning Xray failed to bind it.
func dokodemoPortBound(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return true
	}
	_ = ln.Close()
	return false
}

// MissingDokodemoPorts returns the TPROXY/dokodemo ports that SHOULD be bound —
// one per enabled L2TP/PPTP/OpenVPN inbound, since that's how their traffic
// reaches Xray — but currently are not. A non-empty result means Xray silently
// failed to bind them on a restart, so those VPNs have no internet until it
// rebinds. Consumed by CheckVpnDokodemoJob to self-heal.
func (s *CoreService) MissingDokodemoPorts() []int {
	var missing []int
	if ins, err := s.l2tpService.GetL2tpInbounds(); err == nil {
		for _, in := range ins {
			if port := s.l2tpService.GetTproxyPort(in); in.Enable && !dokodemoPortBound(port) {
				missing = append(missing, port)
			}
		}
	}
	if ins, err := s.pptpService.GetPptpInbounds(); err == nil {
		for _, in := range ins {
			if port := s.pptpService.GetTproxyPort(in); in.Enable && !dokodemoPortBound(port) {
				missing = append(missing, port)
			}
		}
	}
	if ins, err := s.openvpnService.GetOpenVpnInbounds(); err == nil {
		for _, in := range ins {
			// One shared dokodemo per OpenVPN inbound (both transports use it).
			if port := s.openvpnService.GetTproxyPort(in); in.Enable && !dokodemoPortBound(port) {
				missing = append(missing, port)
			}
		}
	}
	return missing
}

// GetCoresStatus returns the status of every backend core, in display order.
func (s *CoreService) GetCoresStatus() []CoreStatus {
	return []CoreStatus{
		s.xrayStatus(),
		s.l2tpStatus(),
		s.pptpStatus(),
		s.openvpnStatus(),
		s.radiusStatus(),
	}
}

func (s *CoreService) xrayStatus() CoreStatus {
	cs := CoreStatus{Name: "xray"}
	if s.xrayService.IsXrayRunning() {
		cs.State = CoreRunning
		cs.Version = s.xrayService.GetXrayVersion()
		return cs
	}
	if err := s.xrayService.GetXrayErr(); err != nil {
		cs.State = CoreError
		cs.Detail = err.Error()
		return cs
	}
	cs.State = CoreStopped
	return cs
}

func (s *CoreService) l2tpStatus() CoreStatus {
	cs := CoreStatus{Name: "l2tp"}
	inbounds, _ := s.l2tpService.GetL2tpInbounds()
	cs.Inbounds = len(inbounds)
	if !daemonInstalled("xl2tpd") {
		cs.State = CoreNotInstalled
		cs.Detail = "xl2tpd not installed"
		return cs
	}
	cs.Version = daemonVersion("xl2tpd")
	cs.Extra = map[string]any{
		"ipsec":     systemctlActive("ipsec"),
		"libreswan": commandExists("ipsec"),
	}
	switch {
	case procMgr.IsRunning("xl2tpd"):
		cs.State = CoreRunning
	case cs.Inbounds == 0:
		cs.State = CoreIdle
	default:
		cs.State = CoreStopped
	}
	return cs
}

func (s *CoreService) pptpStatus() CoreStatus {
	cs := CoreStatus{Name: "pptp"}
	inbounds, _ := s.pptpService.GetPptpInbounds()
	cs.Inbounds = len(inbounds)
	if !daemonInstalled("pptpd") {
		cs.State = CoreNotInstalled
		cs.Detail = "pptpd not installed"
		return cs
	}
	cs.Version = daemonVersion("pptpd")
	switch {
	case procMgr.IsRunning("pptpd"):
		cs.State = CoreRunning
	case cs.Inbounds == 0:
		cs.State = CoreIdle
	default:
		cs.State = CoreStopped
	}
	return cs
}

func (s *CoreService) openvpnStatus() CoreStatus {
	cs := CoreStatus{Name: "openvpn"}
	inbounds, _ := s.openvpnService.GetOpenVpnInbounds()
	cs.Inbounds = len(inbounds)
	if !daemonInstalled("openvpn") {
		cs.State = CoreNotInstalled
		cs.Detail = "openvpn not installed"
		return cs
	}
	cs.Version = daemonVersion("openvpn")
	switch {
	case procMgr.AnyRunningWithPrefix("openvpn-server-"):
		cs.State = CoreRunning
	case cs.Inbounds == 0:
		cs.State = CoreIdle
	default:
		cs.State = CoreStopped
	}
	return cs
}

func (s *CoreService) radiusStatus() CoreStatus {
	cs := CoreStatus{Name: "radius"}
	// RADIUS is embedded in the panel binary, so its version is the panel's.
	cs.Version = config.GetVersion()
	// The embedded RADIUS server binds 127.0.0.1:1812 (auth). If the port can't
	// be bound, the server is already listening — which is what we want.
	pc, err := net.ListenPacket("udp", "127.0.0.1:1812")
	if err != nil {
		cs.State = CoreRunning
		return cs
	}
	_ = pc.Close()
	cs.State = CoreStopped
	return cs
}

// --------------------------------------------------------------------------- //
//  System / kernel status
// --------------------------------------------------------------------------- //

// GetSystemStatus reports the host prerequisites (kernel modules, ip_forward,
// nftables) that cannot be baked into the binary.
func (s *CoreService) GetSystemStatus() SystemStatus {
	st := SystemStatus{
		IpForward: procFileIsOne("/proc/sys/net/ipv4/ip_forward"),
		Nftables:  commandExists("nft"),
		Iproute:   commandExists("ip"),
		ModulesOK: true,
	}
	for _, m := range vpnKernelModules {
		loaded := moduleLoaded(m)
		if !loaded {
			st.ModulesOK = false
		}
		st.Modules = append(st.Modules, ModuleStatus{Name: m, Loaded: loaded})
	}
	return st
}

// IsProvisioned reports whether the VPN backend setup ("Initialize Setup") has
// been completed. It is true when the persisted flag is set, or — for installs
// provisioned before that flag existed — when the host already looks prepared:
// IP forwarding is enabled and a bundled daemon is available (daemons are only
// extracted by Provision). This fallback keeps already-set-up upgrades from
// regressing to the setup call-to-action.
func (s *CoreService) IsProvisioned() bool {
	var ss SettingService
	if ss.GetVpnProvisioned() {
		return true
	}
	return procFileIsOne("/proc/sys/net/ipv4/ip_forward") && daemonInstalled("openvpn")
}

// --------------------------------------------------------------------------- //
//  Control + provisioning
// --------------------------------------------------------------------------- //

// RestartCore restarts the daemon(s) for a given core.
func (s *CoreService) RestartCore(name string) error {
	switch name {
	case "xray":
		return s.xrayService.RestartXray(true)
	case "l2tp":
		return s.l2tpService.RestartServices()
	case "pptp":
		return s.pptpService.RestartServices()
	case "openvpn":
		return s.openvpnService.RestartServices()
	case "radius":
		return RestartRadius()
	default:
		return fmt.Errorf("unknown core: %s", name)
	}
}

// RestartAll restarts every core in a sensible order, aggregating any errors so
// one failing core doesn't abort the rest.
func (s *CoreService) RestartAll() error {
	var errs []string
	for _, name := range []string{"xray", "l2tp", "pptp", "openvpn", "radius"} {
		if err := s.RestartCore(name); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", name, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// StopCore stops a core, where stopping is supported.
func (s *CoreService) StopCore(name string) error {
	switch name {
	case "xray":
		return s.xrayService.StopXray()
	case "l2tp":
		s.l2tpService.StopServices()
		return nil
	case "pptp":
		s.pptpService.StopServices()
		return nil
	case "openvpn":
		s.openvpnService.StopServices()
		return nil
	case "radius":
		return StopRadius()
	default:
		return fmt.Errorf("core %s does not support stop", name)
	}
}

// CoreLogs returns recent captured output for a core. VPN daemons return their
// supervised child-process output; xray/radius return the matching lines from
// the panel's in-memory log buffer (their output is routed there).
func (s *CoreService) CoreLogs(name string) string {
	switch name {
	case "l2tp":
		return procMgr.Logs("xl2tpd")
	case "pptp":
		return procMgr.Logs("pptpd")
	case "openvpn":
		return procMgr.LogsByPrefix("openvpn-server-")
	case "xray":
		out := filterLogs("xray")
		if out == "" {
			return s.xrayService.GetXrayResult()
		}
		return out
	case "radius":
		return filterLogs("radius")
	}
	return ""
}

// filterLogs returns the most recent panel log lines (chronological) whose text
// mentions the given keyword (case-insensitive).
func filterLogs(keyword string) string {
	lines := logger.GetLogs(400, "debug")
	kw := strings.ToLower(keyword)
	var matched []string
	// GetLogs returns newest-first; walk backwards to emit chronological order.
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.Contains(strings.ToLower(lines[i]), kw) {
			matched = append(matched, lines[i])
		}
	}
	return strings.Join(matched, "\n")
}

// Provision performs the host/kernel preparation that no bundled binary can do:
// load + persist the required kernel modules and enable + persist IP forwarding.
// It is idempotent and safe to run repeatedly. This is the in-binary replacement
// for the host-prep half of setup-vpn-backend.sh. It collects and returns all
// steps; use StartProvision for the streamed, non-blocking variant.
func (s *CoreService) Provision() []ProvisionStep {
	var steps []ProvisionStep
	s.runProvisionSteps(func(st ProvisionStep) { steps = append(steps, st) })
	return steps
}

// runProvisionSteps performs each provisioning action and invokes emit after
// every step, so callers can stream progress to a live log. It is idempotent.
// It returns the kernel modules that will only load after a reboot (empty when
// none) together with the package that provides them, so the caller can prompt
// the operator to reboot.
func (s *CoreService) runProvisionSteps(emit func(ProvisionStep)) (rebootModules []string, rebootPkg string) {
	for _, m := range vpnKernelModules {
		if moduleLoaded(m) {
			emit(ProvisionStep{Name: "module " + m, OK: true, Msg: "already loaded"})
			continue
		}
		out, err := exec.Command("modprobe", m).CombinedOutput()
		if err == nil {
			emit(ProvisionStep{Name: "modprobe " + m, OK: true, Msg: "loaded"})
		} else {
			// Not present in the running kernel. Expected on minimal/cloud images;
			// the kernel-modules step below installs it (rebooting into a fuller
			// kernel when the module only ships there). Flag as a warning, not an
			// error, so the console doesn't look broken mid-run.
			emit(ProvisionStep{Name: "modprobe " + m, OK: true, Warn: true,
				Msg: "not in the running kernel — resolving below", Log: strings.TrimSpace(string(out))})
		}
	}

	modConf := strings.Join(vpnKernelModules, "\n") + "\n"
	err := os.WriteFile("/etc/modules-load.d/vpn-ui.conf", []byte(modConf), 0644)
	emit(ProvisionStep{Name: "persist /etc/modules-load.d/vpn-ui.conf", OK: err == nil, Msg: msgOrOK(err)})

	err = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	emit(ProvisionStep{Name: "sysctl net.ipv4.ip_forward=1", OK: err == nil, Msg: msgOrOK(err)})

	// Persist ip_forward plus loose rp_filter. Fedora/RHEL default rp_filter to
	// strict (1), which drops the policy-routed TPROXY packets carrying VPN client
	// traffic into Xray; loose (2, Ubuntu's default) fixes it. This 99-*.conf sorts
	// after Fedora's 50-default.conf, so it wins on boot.
	const sysctlConf = "net.ipv4.ip_forward=1\n" +
		"net.ipv4.conf.all.rp_filter=2\n" +
		"net.ipv4.conf.default.rp_filter=2\n"
	err = os.WriteFile("/etc/sysctl.d/99-vpn-ui.conf", []byte(sysctlConf), 0644)
	emit(ProvisionStep{Name: "persist /etc/sysctl.d/99-vpn-ui.conf", OK: err == nil, Msg: msgOrOK(err)})

	// Apply loose rp_filter now and, when firewalld is active (Fedora/RHEL), trust
	// the VPN address space so its default-drop INPUT policy doesn't block the
	// TPROXY'd data plane. No-op on Debian/Ubuntu.
	ensureVpnHostNetworking()
	emit(ProvisionStep{Name: "relax rp_filter + trust VPN in firewalld", OK: true, Msg: firewallStepMsg()})

	// Extract the daemons baked into the binary and generate their systemd units.
	// On a build without an embedded bundle this is a no-op.
	if backend.Available() {
		files, exErr := backend.Extract()
		emit(ProvisionStep{Name: "extract bundled daemons", OK: exErr == nil, Msg: filesMsg(files, exErr)})

		// pppd ships as a relocatable tree (it dlopens radius.so + OpenSSL
		// providers, so it can't be one static binary). Extract it and, if the
		// host has no pppd of its own, point /usr/sbin/pppd + /usr/lib/pppd at the
		// bundle so both the daemon and its plugins resolve to it.
		if backend.HasPppdBundle() {
			pErr := backend.ExtractPppdBundle()
			emit(ProvisionStep{Name: "extract pppd bundle", OK: pErr == nil, Msg: msgOrOK(pErr)})
			lErr := backend.LinkSystemPppd()
			emit(ProvisionStep{Name: "link system pppd", OK: lErr == nil, Msg: msgOrOK(lErr)})
			plErr := backend.LinkPluginDir()
			emit(ProvisionStep{Name: "link pppd plugin dir", OK: plErr == nil, Msg: msgOrOK(plErr)})
		}

		// pptpd execs pptpctrl from a fixed compiled-in path; point it at the
		// extracted bundle so pptpd works from any install dir.
		clErr := backend.LinkPptpCtrl()
		emit(ProvisionStep{Name: "link pptpctrl", OK: clErr == nil, Msg: msgOrOK(clErr)})

		// The bundled daemons run as child processes of the panel (not systemd),
		// so any leftover units from the old design are torn down here.
		migrateFromSystemd()
		emit(ProvisionStep{Name: "run daemons as child processes", OK: true, Msg: "ok"})
	}

	// The VPN data plane needs nftables (TPROXY steering + traffic accounting) and
	// iproute2 (the fwmark → table 100 policy route). They're present on almost
	// every host, but minimal cloud/container images can omit them — without them
	// clients connect but no traffic routes. Install when missing (no-op if present).
	emit(ensureCommand("nftables", "nft", nftablesPackage))
	emit(ensureCommand("iproute2 (ip)", "ip", iproutePackage))

	// libreswan (IPsec for L2TP/IPsec) is the one VPN daemon that can't be baked
	// into the binary, so install it from the host package manager.
	emit(ensureLibreswan())

	// L2TP/PPTP need PPP kernel modules that minimal/cloud kernels omit. Best-
	// effort install of the distro's full kernel-modules package. When the modules
	// ship only in a newer kernel, this reports that a reboot is needed to load them.
	return s.provisionKernelModules(emit)
}

// provisionKernelModules makes the VPN PPP/L2TP kernel modules available when the
// running kernel lacks them. It is best-effort and non-interactive: it installs
// the right package for the distro, loads what it can into the running kernel,
// and — when the modules only ship in a fuller kernel it had to install — pins
// that kernel in the bootloader and reports that a reboot is needed (rather than
// rebooting). It returns the modules that only load after a reboot and the
// package that was installed.
//
// Per-distro behaviour (see KernelModulesPackage / InstallKernelModules):
//   - Ubuntu: linux-modules-extra-<running> adds modules to the RUNNING kernel →
//     no reboot. Cut-down flavours (kvm) fall back to linux-generic → reboot.
//   - Debian: cloud images omit PPP/L2TP, so the generic linux-image-<arch> is
//     installed → reboot, and the bootloader is pinned to it (a same-version
//     cloud kernel would otherwise stay the GRUB default).
//   - Fedora/RHEL/Alma/CentOS: kernel-modules-extra-<running> → no reboot.
//   - Arch: stock kernel already ships the modules → nothing to do.
func (s *CoreService) provisionKernelModules(emit func(ProvisionStep)) (rebootModules []string, rebootPkg string) {
	missing := s.MissingKernelModules()
	if len(missing) == 0 {
		return nil, ""
	}
	distro := distroPretty()

	pkg := KernelModulesPackage()
	if pkg == "" {
		emit(ProvisionStep{Name: "kernel modules", OK: false,
			Msg: "missing " + strings.Join(missing, ", ") + " on " + distro +
				" — no kernel-modules package known for this distro; load them manually"})
		return nil, ""
	}

	emit(ProvisionStep{Name: "kernel modules (" + distro + ")", OK: true,
		Msg: "missing " + strings.Join(missing, ", ") + " — installing " + pkg})

	installed, still, newKernel, log, err := s.InstallKernelModules()
	if err != nil {
		emit(ProvisionStep{Name: "install " + pkg, OK: false, Msg: err.Error(), Log: log})
		return nil, ""
	}
	if len(still) == 0 {
		emit(ProvisionStep{Name: "install " + installed, OK: true,
			Msg: "modules loaded into the running kernel — no reboot needed", Log: log})
		return nil, ""
	}

	// Whatever is still missing only exists in a freshly installed kernel that
	// isn't booted yet. Report it and make the bootloader boot that kernel.
	if newKernel == "" {
		emit(ProvisionStep{Name: "install " + installed, OK: true, Warn: true,
			Msg: "installed; " + strings.Join(still, ", ") + " load after a reboot into the new kernel", Log: log})
		return still, installed
	}

	emit(ProvisionStep{Name: "install " + installed, OK: true, Warn: true,
		Msg: "installed kernel " + newKernel + "; " + strings.Join(still, ", ") + " load after reboot", Log: log})

	bootMsg, bootErr := ensureBootloaderBootsKernel(newKernel)
	emit(ProvisionStep{Name: "set default boot kernel", OK: bootErr == nil, Msg: bootStepMsg(bootMsg, bootErr)})

	return still, installed
}

func bootStepMsg(msg string, err error) string {
	if err != nil {
		return err.Error()
	}
	return msg
}

// provisionRun holds the state of the single, in-progress or most-recent
// background provisioning run, so the Core Settings page can poll a live log.
// Provisioning is single-admin and one-at-a-time, so one global run suffices.
var provisionRun struct {
	mu             sync.Mutex
	running        bool
	done           bool
	steps          []ProvisionStep
	rebootRequired bool
	rebootModules  []string
	rebootPkg      string
}

// StartProvision launches provisioning in the background and returns true, or
// returns false without starting a second run if one is already in progress.
// On completion it persists the provisioned flag so the setup gate clears.
func (s *CoreService) StartProvision() bool {
	provisionRun.mu.Lock()
	if provisionRun.running {
		provisionRun.mu.Unlock()
		return false
	}
	provisionRun.running = true
	provisionRun.done = false
	provisionRun.steps = nil
	provisionRun.rebootRequired = false
	provisionRun.rebootModules = nil
	provisionRun.rebootPkg = ""
	provisionRun.mu.Unlock()

	go func() {
		var cs CoreService // CoreService is zero-value usable and stateless
		mods, pkg := cs.runProvisionSteps(func(st ProvisionStep) {
			provisionRun.mu.Lock()
			provisionRun.steps = append(provisionRun.steps, st)
			provisionRun.mu.Unlock()
		})
		var ss SettingService
		if err := ss.SetVpnProvisioned(true); err != nil {
			logger.Warning("failed to persist vpnProvisioned flag:", err)
		}
		provisionRun.mu.Lock()
		provisionRun.running = false
		provisionRun.done = true
		provisionRun.rebootRequired = len(mods) > 0
		provisionRun.rebootModules = mods
		provisionRun.rebootPkg = pkg
		provisionRun.mu.Unlock()
	}()
	return true
}

// ProvisionRunState is a snapshot of the background provisioning run, returned to
// the Core Settings page as it polls for live progress.
type ProvisionRunState struct {
	Running        bool            `json:"running"`
	Done           bool            `json:"done"`
	Steps          []ProvisionStep `json:"steps"`
	RebootRequired bool            `json:"rebootRequired"`
	RebootModules  []string        `json:"rebootModules"`
	RebootPkg      string          `json:"rebootPkg"`
}

// ProvisionState returns the current/most-recent provisioning run's progress: a
// copy of the steps emitted so far, whether it is running or done, and whether a
// reboot is needed to finish (kernel modules that only load on a fresh boot).
func (s *CoreService) ProvisionState() ProvisionRunState {
	provisionRun.mu.Lock()
	defer provisionRun.mu.Unlock()
	steps := make([]ProvisionStep, len(provisionRun.steps))
	copy(steps, provisionRun.steps)
	mods := make([]string, len(provisionRun.rebootModules))
	copy(mods, provisionRun.rebootModules)
	return ProvisionRunState{
		Running:        provisionRun.running,
		Done:           provisionRun.done,
		Steps:          steps,
		RebootRequired: provisionRun.rebootRequired,
		RebootModules:  mods,
		RebootPkg:      provisionRun.rebootPkg,
	}
}

// Reboot restarts the host machine after a short delay so the in-flight HTTP
// response is delivered first. It is used to load kernel modules that a
// provisioning package added but that only become active in a freshly booted
// kernel (L2TP/PPTP on minimal cloud images).
func (s *CoreService) Reboot() error {
	if !commandExists("systemctl") && !commandExists("reboot") && !commandExists("shutdown") {
		return fmt.Errorf("no reboot command available on this host")
	}
	go func() {
		time.Sleep(1500 * time.Millisecond)
		if commandExists("systemctl") {
			if err := exec.Command("systemctl", "reboot").Run(); err == nil {
				return
			}
		}
		if commandExists("reboot") {
			if err := exec.Command("reboot").Run(); err == nil {
				return
			}
		}
		_ = exec.Command("shutdown", "-r", "now").Run()
	}()
	return nil
}

func filesMsg(files []string, err error) string {
	if err != nil {
		return err.Error()
	}
	if len(files) == 0 {
		return "nothing to do"
	}
	return fmt.Sprintf("%d file(s)", len(files))
}

// firewallStepMsg summarizes what ensureVpnHostNetworking did, for the setup output.
func firewallStepMsg() string {
	if firewalldRunning() {
		return "firewalld active — trusted " + vpnAddrSpace
	}
	return "rp_filter set loose; no active firewalld"
}

func msgOrOK(err error) string {
	if err != nil {
		return err.Error()
	}
	return "ok"
}
