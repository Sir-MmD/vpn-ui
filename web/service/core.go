package service

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/backend"
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
	cs.Extra = map[string]any{
		"ipsec":     systemctlActive("ipsec"),
		"libreswan": commandExists("ipsec"),
	}
	switch {
	case systemctlActive("xl2tpd"):
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
	switch {
	case systemctlActive("pptpd"):
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
	running := false
	for _, ib := range inbounds {
		if systemctlActive(fmt.Sprintf("openvpn-server@server-%d-udp", ib.Id)) ||
			systemctlActive(fmt.Sprintf("openvpn-server@server-%d-tcp", ib.Id)) {
			running = true
			break
		}
	}
	switch {
	case running:
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
	default:
		return fmt.Errorf("unknown core: %s", name)
	}
}

// StopCore stops a core, where stopping is supported.
func (s *CoreService) StopCore(name string) error {
	switch name {
	case "xray":
		return s.xrayService.StopXray()
	case "openvpn":
		s.openvpnService.StopServices()
		return nil
	default:
		return fmt.Errorf("core %s does not support stop", name)
	}
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

	err = os.WriteFile("/etc/sysctl.d/99-vpn-ui.conf", []byte("net.ipv4.ip_forward=1\n"), 0644)
	steps = append(steps, ProvisionStep{Name: "persist /etc/sysctl.d/99-vpn-ui.conf", OK: err == nil, Msg: msgOrOK(err)})

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

		units, unErr := backend.WriteUnits(backend.BinDir())
		steps = append(steps, ProvisionStep{Name: "write systemd units", OK: unErr == nil, Msg: filesMsg(units, unErr)})
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

func msgOrOK(err error) string {
	if err != nil {
		return err.Error()
	}
	return "ok"
}
