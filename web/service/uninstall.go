package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v2/backend"
	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/logger"
)

// UninstallOptions configures a host teardown.
type UninstallOptions struct {
	// ExePath is the running panel binary, used to kill any *other* panel
	// instance and to resolve a relative bin/ dir against the binary's directory.
	ExePath string
}

// UninstallReport records the outcome of a best-effort teardown: what was
// removed, what was deliberately kept (and must be removed by hand), and any
// errors encountered along the way (teardown never aborts on a single failure).
type UninstallReport struct {
	Removed []string
	Kept    []string
	Errors  []string
}

func (r *UninstallReport) fail(what string, err error) {
	r.Errors = append(r.Errors, fmt.Sprintf("%s: %v", what, err))
}

// Uninstall reverses everything the panel installs on the host. It is the
// inverse of provisioning + `--systemd`, ordered processes/services → firewall
// → routing → files so nothing is in use when its backing files are removed. The
// database and the binary itself are left to the caller (main.runUninstall).
//
// Distro packages (libreswan, nftables, iproute2, kernel modules) and the
// irreversible boot-default / modprobe-blacklist edits are intentionally kept
// and reported for the operator. Must run as root.
func Uninstall(opts UninstallOptions) *UninstallReport {
	r := &UninstallReport{}
	logger.Info("uninstall: starting host teardown")

	// 1. The panel's own systemd unit (default "vpn-ui"). disable --now stops it
	//    without self-killing: this process was started outside that unit's PID.
	var sd SystemdService
	name := sd.GetServiceName()
	if err := sd.RemoveService(name); err != nil {
		r.fail("remove systemd unit "+name, err)
	} else {
		r.Removed = append(r.Removed, unitPath(name))
	}

	// 2. Stop/kill the daemons a live panel supervised (our fresh process's
	//    procMgr is empty, so fall back to pkill by resolved binary path).
	stopVpnDaemons(r, opts.ExePath)

	// 3. Host ipsec.service (only present on the non-bundled libreswan path).
	if commandExists("systemctl") {
		_, _ = systemctl("disable", "--now", "ipsec")
	}

	// 4. Cloudflare warp-cli (SOCKS5), via its own bundled uninstaller.
	uninstallWarpSocks(r)

	// 5. Legacy per-daemon systemd units (superseded by the child-process design;
	//    removed defensively in case an old install left them behind).
	for _, u := range []string{"xl2tpd", "openvpn-server@", "pptpd"} {
		p := unitPath(u)
		if _, err := os.Lstat(p); err == nil {
			if commandExists("systemctl") {
				_, _ = systemctl("disable", "--now", u)
			}
			removePath(r, p)
		}
	}
	if commandExists("systemctl") {
		_, _ = systemctl("daemon-reload")
	}

	// 6. nftables table + legacy iptables chains + firewalld trust.
	if commandExists("nft") {
		_ = exec.Command("nft", "delete", "table", "ip", "vpn").Run()
	}
	(&NftService{}).CleanupLegacyIptables()
	if firewalldRunning() {
		_ = exec.Command("firewall-cmd", "--zone=trusted", "--remove-source="+vpnAddrSpace).Run()
		_ = exec.Command("firewall-cmd", "--permanent", "--zone=trusted", "--remove-source="+vpnAddrSpace).Run()
	}

	// 7. Policy routing (fwmark 1 → table 100). Not reversed anywhere else.
	if commandExists("ip") {
		// There may be more than one identical rule; delete until none remain.
		for i := 0; i < 10; i++ {
			if err := exec.Command("ip", "rule", "del", "fwmark", "1", "lookup", "100").Run(); err != nil {
				break
			}
		}
		_ = exec.Command("ip", "route", "flush", "table", "100").Run()
	}

	// 8. /etc configs, runtime dirs, seq files, logs.
	for _, p := range []string{
		"/etc/vpn-ui", // nft config dir (vpn.nft)
		"/etc/xl2tpd/xl2tpd.conf",
		"/etc/ppp/options.xl2tpd",
		"/etc/ipsec.conf",
		"/etc/ipsec.secrets",
		"/etc/pptpd.conf",
		"/etc/ppp/pptpd-options",
		"/etc/ppp/radius", // panel-owned subdir of the host /etc/ppp
		"/etc/swanctl/conf.d/l2tp.conf",
		"/etc/modules-load.d/vpn-ui.conf",
		"/etc/sysctl.d/99-vpn-ui.conf",
	} {
		removePath(r, p)
	}
	// Per-inbound OpenVPN config dirs (/etc/openvpn/server-<id>).
	if matches, _ := filepath.Glob("/etc/openvpn/server-*"); len(matches) > 0 {
		for _, m := range matches {
			removePath(r, m)
		}
	}
	for _, p := range []string{"/var/run/xl2tpd", "/var/run/openvpn", "/run/pluto"} {
		removePath(r, p)
	}
	if matches, _ := filepath.Glob("/var/run/radius-*.seq"); len(matches) > 0 {
		for _, m := range matches {
			removePath(r, m)
		}
	}
	removePath(r, config.GetLogFolder()) // /var/log/vpn-ui
	removePath(r, "/var/log/pluto.log")

	// 9. Bundled daemon trees + their host symlinks. Remove the outward symlinks
	//    ONLY when they point into our bundle, so a distro-native pppd is never
	//    unlinked; then remove the bundle root itself (pptpctrl link lives inside).
	removeSymlinkIfTarget(r, backend.PppdSystem, backend.PppdBundled)
	removeSymlinkIfTarget(r, backend.PppdPluginDir, backend.PppdBundleRoot+"/lib/pppd")
	removePath(r, backend.PppdBundleRoot) // /usr/libexec/vpn-ui (incl. libreswan/, pptpctrl)
	if usingBundledIpsec() {
		removePath(r, backend.LibreswanNssDir) // /etc/ipsec.d — only ours on the bundled path
	}

	// 10. The bin/ dir next to the binary (xray core, geo files, config.json,
	//     backend/bin daemons). Resolve a relative path against the exe's dir so
	//     it works regardless of the caller's working directory.
	binDir := config.GetBinFolderPath()
	if !filepath.IsAbs(binDir) {
		base := "."
		if opts.ExePath != "" {
			base = filepath.Dir(opts.ExePath)
		}
		binDir = filepath.Join(base, binDir)
	}
	removePath(r, binDir)

	// 11. Kept — not removed (shared, or irreversible without a backup we never took).
	r.Kept = append(r.Kept,
		"distro packages (libreswan, nftables, iproute2/iproute, kernel-modules-extra) — remove with your package manager if unused elsewhere",
		"GRUB boot-default pin (GRUB_DEFAULT=saved in /etc/default/grub) — not reversible without your original",
		"/etc/modprobe.d un-blacklist edits — not reversible without your original",
	)

	logger.Info("uninstall: host teardown complete")
	return r
}

// stopVpnDaemons stops the supervised VPN daemons. procMgr.StopAll covers
// daemons this process started (a no-op for a fresh --uninstall invocation);
// pkill by resolved binary path then catches daemons a separately-running panel
// spawned, mirroring procmgr.go's orphan cleanup.
func stopVpnDaemons(r *UninstallReport, exePath string) {
	procMgr.StopAll()
	if !commandExists("pkill") {
		return
	}
	for _, d := range []string{"openvpn", "xl2tpd", "pptpd"} {
		bin := daemonBin(d)
		if bin == d {
			continue // unresolved bare name — avoid a too-broad match
		}
		_ = exec.Command("pkill", "-KILL", "-f", bin).Run()
	}
	_ = exec.Command("pkill", "-KILL", "-f", backend.LibreswanBundleRoot+"/libexec/ipsec/pluto.bin").Run()

	// Kill any OTHER panel process (e.g. the one the just-removed unit ran).
	// Exclude ourselves AND our ancestor chain: `pgrep -f <exePath>` also matches
	// the wrapper that launched us (under `incus exec`/ssh, `sh -c "<exePath>
	// --uninstall ..."` carries the exe path), and killing that parent severs the
	// caller's exec channel -> spurious 255 exit though teardown still completes.
	if exePath == "" {
		return
	}
	skip := map[string]bool{}
	for pid := os.Getpid(); pid > 1; {
		skip[strconv.Itoa(pid)] = true
		ppid := parentPID(pid)
		if ppid <= 1 || ppid == pid {
			break
		}
		pid = ppid
	}
	out, _ := exec.Command("pgrep", "-f", exePath).Output()
	for _, pid := range strings.Fields(string(out)) {
		if skip[pid] {
			continue
		}
		_ = exec.Command("kill", "-KILL", pid).Run()
	}
}

// parentPID returns the parent PID of pid by reading /proc/<pid>/stat, or 0 if it
// can't be determined. The comm field (2nd) may contain spaces and parentheses, so
// parse the fields AFTER the last ')': ppid is the second of those.
func parentPID(pid int) int {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	s := string(data)
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+1 >= len(s) {
		return 0
	}
	fields := strings.Fields(s[i+1:])
	if len(fields) < 2 {
		return 0
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0
	}
	return ppid
}

// uninstallWarpSocks removes the official Cloudflare warp-cli (if present) via
// its bundled installer's --uninstall path, blocking until the background run
// finishes — a returning CLI would otherwise kill the goroutine mid-uninstall.
func uninstallWarpSocks(r *UninstallReport) {
	if !WarpSocksInstalled() {
		return
	}
	logger.Info("uninstall: removing cloudflare warp-cli")
	if !StartWarpSocks("uninstall", 0) {
		r.fail("warp uninstall", fmt.Errorf("another warp-cli run is already in progress"))
		return
	}
	deadline := time.Now().Add(150 * time.Second)
	for time.Now().Before(deadline) {
		if st := WarpSocksState(); st.Done {
			if st.Success {
				r.Removed = append(r.Removed, "cloudflare-warp (warp-cli SOCKS)")
			} else {
				r.fail("warp uninstall", fmt.Errorf("uninstaller reported failure"))
			}
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	r.fail("warp uninstall", fmt.Errorf("timed out after 3m"))
}

// removePath deletes a file or directory tree, recording the outcome. A path
// that's already absent is silently skipped (not an error).
func removePath(r *UninstallReport, path string) {
	if path == "" {
		return
	}
	if _, err := os.Lstat(path); err != nil {
		if !os.IsNotExist(err) {
			r.fail("stat "+path, err)
		}
		return
	}
	if err := os.RemoveAll(path); err != nil {
		r.fail("remove "+path, err)
		return
	}
	r.Removed = append(r.Removed, path)
}

// removeSymlinkIfTarget removes link only when it is a symlink pointing at
// wantTarget — so we never unlink a distro's own file that happens to share the
// path (e.g. a host-native /usr/sbin/pppd).
func removeSymlinkIfTarget(r *UninstallReport, link, wantTarget string) {
	dest, err := os.Readlink(link)
	if err != nil || dest != wantTarget {
		return
	}
	if err := os.Remove(link); err != nil {
		r.fail("remove symlink "+link, err)
		return
	}
	r.Removed = append(r.Removed, link+" -> "+wantTarget)
}
