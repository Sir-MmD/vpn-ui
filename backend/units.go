package backend

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// xl2tpdUnit returns a systemd unit for the bundled xl2tpd, with ExecStart
// pointing at the extracted binary in binDir. The source-built xl2tpd ships no
// unit, and Fedora/RHEL don't package one at all, so the panel provides it.
func xl2tpdUnit(binDir, envLine string) string {
	return fmt.Sprintf(`[Unit]
Description=Level 2 Tunnel Protocol Daemon (L2TP) [vpn-ui bundled]
After=network-online.target ipsec.service
Wants=ipsec.service

[Service]
Type=simple
%sExecStartPre=-/usr/bin/mkdir -p /var/run/xl2tpd
ExecStart=%s/xl2tpd -D
PIDFile=/run/xl2tpd/xl2tpd.pid
Restart=on-abort

[Install]
WantedBy=multi-user.target
`, envLine, binDir)
}

// openvpnTemplateUnit returns a systemd template unit (openvpn-server@.service)
// for the bundled openvpn. The panel starts instances as
// openvpn-server@server-{id}-{proto}, whose %i.conf lives (via symlink) under
// /etc/openvpn/server. The bundled openvpn is built without systemd support, so
// this uses Type=simple (the panel's config runs openvpn in the foreground).
func openvpnTemplateUnit(binDir string) string {
	return fmt.Sprintf(`[Unit]
Description=OpenVPN service for %%I [vpn-ui bundled]
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/etc/openvpn/server
ExecStart=%s/openvpn --suppress-timestamps --config %%i.conf
CapabilityBoundingSet=CAP_IPC_LOCK CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SETGID CAP_SETUID CAP_SYS_CHROOT CAP_DAC_OVERRIDE CAP_AUDIT_WRITE
DeviceAllow=/dev/net/tun rw
KillMode=process
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
`, binDir)
}

// pptpdUnit returns a systemd unit for the bundled pptpd. The panel manages a
// single pptpd (systemctl restart pptpd) that reads /etc/pptpd.conf (generated
// by the panel). --fg keeps it in the foreground for Type=simple.
func pptpdUnit(binDir, envLine, pppArg string) string {
	return fmt.Sprintf(`[Unit]
Description=PoPToP PPTP Server [vpn-ui bundled]
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
%sExecStart=%s/pptpd --fg%s
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
`, envLine, binDir, pppArg)
}

// LinkPptpCtrl points the fixed path pptpd was compiled to exec pptpctrl from
// (PptpCtrlLink) at the extracted bundled pptpctrl, so the bundle works from any
// install dir. No-op when pptpctrl isn't bundled. Idempotent.
func LinkPptpCtrl() error {
	ctrl := DaemonPath("pptpctrl")
	if ctrl == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(PptpCtrlLink), 0o755); err != nil {
		return err
	}
	_ = os.Remove(PptpCtrlLink)
	return os.Symlink(ctrl, PptpCtrlLink)
}

// distroUnitExists reports whether a distro package already provides this unit
// (in /usr/lib or /lib). If so we leave it alone and use the packaged daemon.
func distroUnitExists(name string) bool {
	for _, dir := range []string{"/usr/lib/systemd/system/", "/lib/systemd/system/"} {
		if _, err := os.Stat(dir + name); err == nil {
			return true
		}
	}
	return false
}

// WriteUnits writes systemd unit files for the bundled daemons that point at the
// extracted binaries, unless the distro already provides that unit. It reloads
// systemd afterwards. Returns the list of unit files written.
func WriteUnits(binDir string) ([]string, error) {
	var written []string

	// When the daemons use the bundled pppd, they need OpenSSL to find the
	// bundled legacy provider (MS-CHAP/MPPE), and pptpd must be told to use the
	// bundled pppd binary. With a system pppd these must NOT be set (its OpenSSL
	// providers differ).
	envLine, pppArg := "", ""
	if UsingBundledPppd() {
		envLine = "Environment=OPENSSL_MODULES=" + OpenSSLModules + "\n"
		pppArg = " --ppp " + PppdBundled
	}

	if DaemonPath("xl2tpd") != "" && !distroUnitExists("xl2tpd.service") {
		path := "/etc/systemd/system/xl2tpd.service"
		if err := os.WriteFile(path, []byte(xl2tpdUnit(binDir, envLine)), 0o644); err != nil {
			return written, err
		}
		written = append(written, path)
	}

	if DaemonPath("openvpn") != "" && !distroUnitExists("openvpn-server@.service") {
		path := "/etc/systemd/system/openvpn-server@.service"
		if err := os.WriteFile(path, []byte(openvpnTemplateUnit(binDir)), 0o644); err != nil {
			return written, err
		}
		written = append(written, path)
	}

	if DaemonPath("pptpd") != "" && !distroUnitExists("pptpd.service") {
		// pptpd execs pptpctrl from the compile-time path PptpCtrlLink; symlink
		// it to the extracted binary so the bundle works from any install dir.
		if ctrl := DaemonPath("pptpctrl"); ctrl != "" {
			_ = os.MkdirAll(filepath.Dir(PptpCtrlLink), 0o755)
			_ = os.Remove(PptpCtrlLink)
			if err := os.Symlink(ctrl, PptpCtrlLink); err != nil {
				return written, err
			}
		}
		path := "/etc/systemd/system/pptpd.service"
		if err := os.WriteFile(path, []byte(pptpdUnit(binDir, envLine, pppArg)), 0o644); err != nil {
			return written, err
		}
		written = append(written, path)
	}

	if len(written) > 0 {
		_ = exec.Command("systemctl", "daemon-reload").Run()
	}
	return written, nil
}
