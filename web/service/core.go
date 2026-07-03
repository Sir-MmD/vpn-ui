package service

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"

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
	"nf_tproxy_ipv4",    // TPROXY (L2TP/PPTP -> Xray)
	"af_key",            // IPsec
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
type ProvisionStep struct {
	Name string `json:"name"`
	OK   bool   `json:"ok"`
	Msg  string `json:"msg"`
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
// for the host-prep half of setup-vpn-backend.sh.
func (s *CoreService) Provision() []ProvisionStep {
	var steps []ProvisionStep

	for _, m := range vpnKernelModules {
		if moduleLoaded(m) {
			steps = append(steps, ProvisionStep{Name: "module " + m, OK: true, Msg: "already loaded"})
			continue
		}
		err := exec.Command("modprobe", m).Run()
		steps = append(steps, ProvisionStep{Name: "modprobe " + m, OK: err == nil, Msg: msgOrOK(err)})
	}

	modConf := strings.Join(vpnKernelModules, "\n") + "\n"
	err := os.WriteFile("/etc/modules-load.d/vpn-ui.conf", []byte(modConf), 0644)
	steps = append(steps, ProvisionStep{Name: "persist /etc/modules-load.d/vpn-ui.conf", OK: err == nil, Msg: msgOrOK(err)})

	err = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	steps = append(steps, ProvisionStep{Name: "sysctl net.ipv4.ip_forward=1", OK: err == nil, Msg: msgOrOK(err)})

	// Persist ip_forward plus loose rp_filter. Fedora/RHEL default rp_filter to
	// strict (1), which drops the policy-routed TPROXY packets carrying VPN client
	// traffic into Xray; loose (2, Ubuntu's default) fixes it. This 99-*.conf sorts
	// after Fedora's 50-default.conf, so it wins on boot.
	const sysctlConf = "net.ipv4.ip_forward=1\n" +
		"net.ipv4.conf.all.rp_filter=2\n" +
		"net.ipv4.conf.default.rp_filter=2\n"
	err = os.WriteFile("/etc/sysctl.d/99-vpn-ui.conf", []byte(sysctlConf), 0644)
	steps = append(steps, ProvisionStep{Name: "persist /etc/sysctl.d/99-vpn-ui.conf", OK: err == nil, Msg: msgOrOK(err)})

	// Apply loose rp_filter now and, when firewalld is active (Fedora/RHEL), trust
	// the VPN address space so its default-drop INPUT policy doesn't block the
	// TPROXY'd data plane. No-op on Debian/Ubuntu.
	ensureVpnHostNetworking()
	steps = append(steps, ProvisionStep{Name: "relax rp_filter + trust VPN in firewalld", OK: true, Msg: firewallStepMsg()})

	// Extract the daemons baked into the binary and generate their systemd units.
	// On a build without an embedded bundle this is a no-op.
	if backend.Available() {
		files, exErr := backend.Extract()
		steps = append(steps, ProvisionStep{Name: "extract bundled daemons", OK: exErr == nil, Msg: filesMsg(files, exErr)})

		// pppd ships as a relocatable tree (it dlopens radius.so + OpenSSL
		// providers, so it can't be one static binary). Extract it and, if the
		// host has no pppd of its own, point /usr/sbin/pppd at the bundle.
		if backend.HasPppdBundle() {
			pErr := backend.ExtractPppdBundle()
			steps = append(steps, ProvisionStep{Name: "extract pppd bundle", OK: pErr == nil, Msg: msgOrOK(pErr)})
			lErr := backend.LinkSystemPppd()
			steps = append(steps, ProvisionStep{Name: "link system pppd", OK: lErr == nil, Msg: msgOrOK(lErr)})
		}

		// pptpd execs pptpctrl from a fixed compiled-in path; point it at the
		// extracted bundle so pptpd works from any install dir.
		clErr := backend.LinkPptpCtrl()
		steps = append(steps, ProvisionStep{Name: "link pptpctrl", OK: clErr == nil, Msg: msgOrOK(clErr)})

		// The bundled daemons run as child processes of the panel (not systemd),
		// so any leftover units from the old design are torn down here.
		migrateFromSystemd()
		steps = append(steps, ProvisionStep{Name: "run daemons as child processes", OK: true, Msg: "ok"})
	}

	// libreswan (IPsec for L2TP/IPsec) is the one VPN daemon that can't be baked
	// into the binary, so install it from the host package manager.
	steps = append(steps, ensureLibreswan())

	return steps
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
