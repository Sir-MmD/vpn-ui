package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// packageManager abstracts the host's package manager. It's used for the one
// VPN dependency that can't be baked into the x-ui binary — libreswan (the
// IPsec daemon for L2TP/IPsec), whose pluto + NSS crypto don't relocate
// reliably. Everything else (xl2tpd, openvpn, pptpd, pppd) ships in the binary.
type packageManager struct {
	name    string   // display name
	env     []string // extra environment (e.g. non-interactive)
	refresh []string // optional index-refresh command
	install []string // install command; the package name is appended
	hint    string   // manual guidance when libreswan isn't in the default repos
}

// detectPackageManager returns the host's package manager, or nil if none of the
// supported ones are present. Detection is by which tool exists, so it works
// across Debian/Ubuntu (apt), Fedora/RHEL 8+ (dnf), RHEL/CentOS 7 (yum),
// openSUSE (zypper), Arch (pacman) and Alpine (apk).
func detectPackageManager() *packageManager {
	switch {
	case commandExists("apt-get"):
		return &packageManager{
			name:    "apt",
			env:     []string{"DEBIAN_FRONTEND=noninteractive"},
			refresh: []string{"apt-get", "update"},
			// Keep existing conffiles on any prompt so an unattended kernel install
			// (which can touch /etc/default/grub, /etc/kernel-img.conf, …) never
			// blocks waiting for a "keep or replace?" answer.
			install: []string{"apt-get", "install", "-y",
				"-o", "Dpkg::Options::=--force-confold",
				"-o", "Dpkg::Options::=--force-confdef"},
		}
	case commandExists("dnf"):
		return &packageManager{name: "dnf", install: []string{"dnf", "install", "-y"}}
	case commandExists("yum"):
		return &packageManager{name: "yum", install: []string{"yum", "install", "-y"}}
	case commandExists("zypper"):
		return &packageManager{
			name:    "zypper",
			install: []string{"zypper", "--non-interactive", "install"},
			hint:    "libreswan isn't in openSUSE's official repos — install it manually (e.g. from a build/OBS repo) then re-run setup",
		}
	case commandExists("pacman"):
		return &packageManager{
			name:    "pacman",
			refresh: []string{"pacman", "-Sy", "--noconfirm"},
			install: []string{"pacman", "-S", "--needed", "--noconfirm"},
			hint:    "libreswan is AUR-only on Arch — install an AUR helper (yay/paru) or build it, then re-run setup",
		}
	case commandExists("apk"):
		return &packageManager{
			name:    "apk",
			refresh: []string{"apk", "update"},
			install: []string{"apk", "add"},
		}
	default:
		return nil
	}
}

// installPackage refreshes the index (when the manager needs it) and installs
// the package, returning the combined command output (for the setup console's
// per-step log) alongside any error. Best-effort refresh — an install can still
// succeed from a warm cache if the refresh fails (e.g. one mirror is down).
func (pm *packageManager) installPackage(pkg string) (string, error) {
	var log strings.Builder
	if len(pm.refresh) > 0 {
		refresh := exec.Command(pm.refresh[0], pm.refresh[1:]...)
		refresh.Env = append(os.Environ(), pm.env...)
		rout, _ := refresh.CombinedOutput()
		log.WriteString("$ " + strings.Join(pm.refresh, " ") + "\n")
		log.Write(rout)
	}
	args := append(append([]string{}, pm.install[1:]...), pkg)
	cmd := exec.Command(pm.install[0], args...)
	cmd.Env = append(os.Environ(), pm.env...)
	out, err := cmd.CombinedOutput()
	log.WriteString("\n$ " + pm.install[0] + " " + strings.Join(args, " ") + "\n")
	log.Write(out)
	if err != nil {
		return log.String(), fmt.Errorf("%v: %s", err, lastNonEmptyLine(string(out)))
	}
	return log.String(), nil
}

func lastNonEmptyLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if t := strings.TrimSpace(lines[i]); t != "" {
			return t
		}
	}
	return ""
}

// ensureLibreswan installs libreswan via the host package manager if it isn't
// already present, initializes its NSS database, and enables + starts the ipsec
// service. The package is named "libreswan" on every major distro. Stock
// libreswan works for modern clients (Windows/macOS/iOS/Android); MikroTik and
// legacy devices that require the MODP1024 DH group need the ALL_ALGS rebuild
// (handled by setup-vpn-backend.sh), which is out of scope here.
func ensureLibreswan() ProvisionStep {
	var log strings.Builder
	if !commandExists("ipsec") {
		pm := detectPackageManager()
		if pm == nil {
			return ProvisionStep{Name: "libreswan (IPsec)", OK: false,
				Msg: "no supported package manager found — install 'libreswan' manually"}
		}
		out, err := pm.installPackage("libreswan")
		log.WriteString(out)
		// Arch keeps libreswan in the AUR, not the official repos, so the pacman
		// install can't find it. Retry through an AUR helper (yay first, then paru).
		if err != nil && pm.name == "pacman" {
			aurOut, aurErr := installLibreswanFromAUR()
			log.WriteString(aurOut)
			err = aurErr
		}
		if err != nil {
			// Surface the ACTUAL install error so the operator sees exactly what went
			// wrong (libreswan not in this distro's repos, no AUR helper, build failure,
			// …) instead of a vague notice. L2TP/IPsec is unavailable until it's fixed,
			// but PPTP/OpenVPN/raw-L2TP still work — so this is a warning, not a hard stop.
			msg := "libreswan install failed — L2TP/IPsec unavailable (PPTP/OpenVPN/raw-L2TP still work): " + err.Error()
			if pm.hint != "" {
				msg += " — " + pm.hint
			}
			return ProvisionStep{Name: "libreswan via " + pm.name, OK: true, Warn: true, Msg: msg, Log: log.String()}
		}
		if !commandExists("ipsec") {
			return ProvisionStep{Name: "libreswan via " + pm.name, OK: true, Warn: true,
				Msg: withHint("libreswan install ran but 'ipsec' still not found — L2TP/IPsec unavailable", pm.hint), Log: log.String()}
		}
	}
	// Fresh installs (notably Ubuntu 24/26 + Libreswan 5.x) ship the NSS database
	// UNinitialized, so the ipsec.service ExecStartPre `ipsec checknss` fails and
	// pluto never starts — the service shows "stopped" and a restart/reboot won't
	// help. Initialize it, then enable + start so IPsec is up and survives reboot.
	nssOut, err := initIpsecNSS()
	log.WriteString("\n$ ipsec checknss\n" + nssOut)
	if err != nil {
		return ProvisionStep{Name: "libreswan (IPsec)", OK: false, Msg: "ipsec checknss failed: " + err.Error(), Log: log.String()}
	}
	log.WriteString(startIpsecService())
	if systemctlActive("ipsec") {
		return ProvisionStep{Name: "libreswan (IPsec)", OK: true, Msg: "installed; NSS initialized; ipsec running", Log: log.String()}
	}
	log.WriteString(ipsecFailureDiagnostics())
	return ProvisionStep{Name: "libreswan (IPsec)", OK: true, Warn: true,
		Msg: "installed; NSS initialized; ipsec not yet active (check `systemctl status ipsec`)", Log: log.String()}
}

// installLibreswanFromAUR installs libreswan through an AUR helper on Arch, where
// it isn't in the official repos. Tries yay first, then paru. Returns the combined
// command output and an error if no helper is present or the build fails. NOTE: AUR
// helpers build packages as a non-root user (makepkg refuses to run as root), so on
// a root-only box this reports that failure verbatim rather than hiding it.
func installLibreswanFromAUR() (string, error) {
	var b strings.Builder
	tried := false
	for _, helper := range []string{"yay", "paru"} {
		if !commandExists(helper) {
			continue
		}
		tried = true
		args := []string{"-S", "--needed", "--noconfirm", "libreswan"}
		out, err := exec.Command(helper, args...).CombinedOutput()
		b.WriteString("\n$ " + helper + " " + strings.Join(args, " ") + "\n")
		b.Write(out)
		if err == nil && commandExists("ipsec") {
			return b.String(), nil
		}
		return b.String(), fmt.Errorf("%s couldn't build libreswan: %s", helper, lastNonEmptyLine(string(out)))
	}
	if !tried {
		return b.String(), fmt.Errorf("no AUR helper found (install yay or paru)")
	}
	return b.String(), fmt.Errorf("AUR install did not produce the 'ipsec' command")
}

// initIpsecNSS initializes libreswan's NSS database if missing, returning the
// command output. `ipsec checknss` creates it when absent and is safe to run
// repeatedly. No-op without ipsec.
func initIpsecNSS() (string, error) {
	if !commandExists("ipsec") {
		return "", nil
	}
	out, err := exec.Command("ipsec", "checknss").CombinedOutput()
	return string(out), err
}

// startIpsecService enables (start-on-boot) and starts the libreswan service,
// returning the command output. Uses systemd where present; falls back to the
// `ipsec start` wrapper otherwise.
func startIpsecService() string {
	if commandExists("systemctl") {
		out, _ := exec.Command("systemctl", "enable", "--now", "ipsec").CombinedOutput()
		return "\n$ systemctl enable --now ipsec\n" + string(out)
	}
	out, _ := exec.Command("ipsec", "start").CombinedOutput()
	return "\n$ ipsec start\n" + string(out)
}

// restartIpsecService (re)starts libreswan, preferring systemd so the unit state
// matches reality — the panel's status check reads `systemctl is-active ipsec`,
// and going through systemd also (re)starts the service on the current boot and
// keeps it enabled. Falls back to the `ipsec restart` wrapper when systemd isn't
// present. Returns the command output for the setup/restart log.
func restartIpsecService() (string, error) {
	if commandExists("systemctl") {
		out, err := exec.Command("systemctl", "restart", "ipsec").CombinedOutput()
		return "\n$ systemctl restart ipsec\n" + string(out), err
	}
	out, err := exec.Command("ipsec", "restart").CombinedOutput()
	return "\n$ ipsec restart\n" + string(out), err
}

// ipsecFailureDiagnostics captures why ipsec.service didn't come up, so the setup
// console shows the real cause (bad ipsec.conf, missing XFRM/af_key module, NSS,
// …) instead of a bare "not active". Best-effort and systemd-only.
func ipsecFailureDiagnostics() string {
	if !commandExists("systemctl") {
		return ""
	}
	var b strings.Builder
	out, _ := exec.Command("systemctl", "status", "ipsec", "--no-pager", "-l").CombinedOutput()
	b.WriteString("\n$ systemctl status ipsec\n" + string(out))
	if jout, _ := exec.Command("journalctl", "-u", "ipsec", "--no-pager", "-n", "30").CombinedOutput(); len(jout) > 0 {
		b.WriteString("\n$ journalctl -u ipsec -n 30\n" + string(jout))
	}
	return b.String()
}

var libreswanVersionRe = regexp.MustCompile(`(\d+)\.(\d+)`)

// libreswanVersion parses the installed Libreswan major.minor from
// `ipsec --version` (e.g. "Linux Libreswan 3.32 (netkey) on …" → 3, 32). ok is
// false when ipsec isn't installed or the version can't be parsed.
func libreswanVersion() (major, minor int, ok bool) {
	if !commandExists("ipsec") {
		return 0, 0, false
	}
	out, _ := exec.Command("ipsec", "--version").CombinedOutput()
	m := libreswanVersionRe.FindStringSubmatch(string(out))
	if m == nil {
		return 0, 0, false
	}
	major, _ = strconv.Atoi(m[1])
	minor, _ = strconv.Atoi(m[2])
	return major, minor, true
}

func withHint(msg, hint string) string {
	if hint == "" {
		return msg
	}
	return msg + " — " + hint
}

// ensureCommand makes sure a required host command is available, installing the
// package that provides it when it's missing. It is a no-op on the ~all hosts
// that already ship the tool (reported as "already present"), so it only touches
// the package manager on minimal cloud/container images. pkgFn resolves the
// package name for the running distro.
func ensureCommand(display, cmd string, pkgFn func() string) ProvisionStep {
	if commandExists(cmd) {
		return ProvisionStep{Name: display, OK: true, Msg: "already present"}
	}
	pkg := pkgFn()
	if pkg == "" {
		return ProvisionStep{Name: display, OK: false,
			Msg: "'" + cmd + "' missing and no package known for this distro — install it manually"}
	}
	pm := detectPackageManager()
	if pm == nil {
		return ProvisionStep{Name: display, OK: false,
			Msg: "'" + cmd + "' missing and no supported package manager — install '" + pkg + "' manually"}
	}
	out, err := pm.installPackage(pkg)
	if err != nil {
		return ProvisionStep{Name: display + " via " + pm.name, OK: false, Msg: err.Error(), Log: out}
	}
	if !commandExists(cmd) {
		return ProvisionStep{Name: display + " via " + pm.name, OK: false,
			Msg: "installed " + pkg + " but '" + cmd + "' still not found", Log: out}
	}
	return ProvisionStep{Name: display + " via " + pm.name, OK: true, Msg: "installed " + pkg, Log: out}
}

// vpnModuleEnableSet is the set of modules whose distro deny-list/disable must be
// cleared so they load at boot: every module the VPN backend uses PLUS each one's
// dependency closure (Fedora/RHEL blacklist several — e.g. loading l2tp_ppp pulls
// the deny-listed l2tp_netlink/l2tp_core). Dependencies are resolved with
// `modprobe --show-depends` (best-effort; only works once the modules are
// installed for the running kernel, which is why the caller runs after the
// kernel-modules install). Unresolvable modules still contribute their own name.
func vpnModuleEnableSet() map[string]bool {
	need := map[string]bool{}
	for _, m := range append(append([]string{}, vpnKernelModules...), vpnOptionalKernelModules...) {
		need[m] = true
		// `modprobe --show-depends` prints one `insmod <path>/<dep>.ko[.xz]` line per
		// module in load order (deps first). Extract each dep's bare module name.
		// (Fails harmlessly for a module the kernel dropped, e.g. af_key on RHEL 10+.)
		out, err := exec.Command("modprobe", "--show-depends", m).CombinedOutput()
		if err != nil {
			continue
		}
		for _, ln := range strings.Split(string(out), "\n") {
			f := strings.Fields(ln)
			if len(f) < 2 || f[0] != "insmod" {
				continue
			}
			base := filepath.Base(f[1])            // foo.ko.xz
			base = strings.SplitN(base, ".", 2)[0] // foo
			if base != "" {
				need[base] = true
			}
		}
	}
	return need
}

// isModuleDisableCommand reports whether an `install <mod> <cmd…>` modprobe.d rule
// is a "never load this module" stub (the RHEL/CIS hardening form). Unlike
// `blacklist` — which only blocks alias auto-load and is bypassed by an explicit
// modprobe — an `install <mod> /bin/false` rule replaces the load entirely, so it
// blocks systemd-modules-load AND an explicit modprobe. Only these no-op stubs are
// neutralised; a real install rule (with side effects) is left alone.
func isModuleDisableCommand(cmd string) bool {
	switch cmd {
	case "/bin/false", "/bin/true", "/usr/bin/false", "/usr/bin/true", "false", "true", ":", "/bin/:":
		return true
	}
	return false
}

// unblacklistVpnModules neutralises any distro modprobe rule that would stop the
// VPN kernel modules (and their dependencies) from loading at boot. Two forms:
//
//   - `blacklist <mod>` (Fedora/RHEL ship /etc/modprobe.d/<mod>-blacklist.conf for
//     the L2TP modules): kmod's deny-list makes systemd-modules-load SKIP the module
//     (journal: "Module '<mod>' is deny-listed (by kmod)"), so the entries in
//     /etc/modules-load.d/vpn-ui.conf never load on boot and L2TP stays down after a
//     reboot until setup is re-run (an explicit modprobe bypasses the deny-list).
//   - `install <mod> /bin/false` (RHEL/CIS hardening form): replaces the load with a
//     no-op, blocking BOTH systemd-modules-load and an explicit modprobe.
//
// There is no "re-enable" directive, so we comment the offending line out: a file
// under /etc or /run is rewritten in place; one under /usr|/lib (package-owned) is
// written commented to /etc/modprobe.d/<same-name>, which overrides the original by
// basename. Applies to every VPN module and its dependency closure, so it covers
// all the modules we use across all distros. Best-effort; returns the cleared
// modules and a log of the files touched.
func unblacklistVpnModules() (cleared []string, log string) {
	need := vpnModuleEnableSet()
	seen := map[string]bool{}
	clear := func(mod string) {
		if !seen[mod] {
			seen[mod] = true
			cleared = append(cleared, mod)
		}
	}
	var b strings.Builder
	for _, dir := range []string{"/etc/modprobe.d", "/run/modprobe.d", "/usr/lib/modprobe.d", "/lib/modprobe.d"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			lines := strings.Split(string(data), "\n")
			modified := false
			for i, ln := range lines {
				f := strings.Fields(ln)
				switch {
				case len(f) >= 2 && f[0] == "blacklist" && need[f[1]]:
					lines[i] = "# " + ln + "    # vpn-ui: required VPN module"
					modified = true
					clear(f[1])
				case len(f) >= 3 && f[0] == "install" && need[f[1]] && isModuleDisableCommand(f[2]):
					lines[i] = "# " + ln + "    # vpn-ui: required VPN module"
					modified = true
					clear(f[1])
				}
			}
			if !modified {
				continue
			}
			// Package-owned rules live under /usr|/lib; write the neutralised copy to
			// /etc where it overrides the original by basename. /etc and /run files are
			// rewritten in place.
			target := filepath.Join(dir, e.Name())
			if strings.HasPrefix(dir, "/usr/") || dir == "/lib/modprobe.d" {
				target = filepath.Join("/etc/modprobe.d", e.Name())
			}
			if err := os.WriteFile(target, []byte(strings.Join(lines, "\n")), 0644); err != nil {
				b.WriteString("failed to write " + target + ": " + err.Error() + "\n")
				continue
			}
			b.WriteString("cleared deny-list/disable in " + target + "\n")
		}
	}
	return cleared, b.String()
}

// nftablesPackage is the package that provides the `nft` CLI. It is named
// "nftables" on every supported distro.
func nftablesPackage() string { return "nftables" }

// iproutePackage is the package that provides the `ip` CLI — "iproute" on the
// RHEL family (dnf/yum), "iproute2" everywhere else.
func iproutePackage() string {
	switch {
	case commandExists("dnf"), commandExists("yum"):
		return "iproute"
	default:
		return "iproute2"
	}
}

// --------------------------------------------------------------------------- //
//  Kernel modules (installing the full kernel on minimal/cloud images)
// --------------------------------------------------------------------------- //

func readTrim(path string) string {
	b, _ := os.ReadFile(path)
	return strings.TrimSpace(string(b))
}

func runningKernel() string { return readTrim("/proc/sys/kernel/osrelease") }

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// osReleaseField returns a value from /etc/os-release (e.g. ID, VERSION_ID,
// ID_LIKE, PRETTY_NAME), unquoted, or "" if absent.
func osReleaseField(key string) string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, key+"="); ok {
			return strings.Trim(v, "\"'")
		}
	}
	return ""
}

// distroPretty is a short human name for the running distro, for the setup log.
func distroPretty() string {
	if p := osReleaseField("PRETTY_NAME"); p != "" {
		return p
	}
	id := osReleaseField("ID")
	if id == "" {
		return "this host"
	}
	if v := osReleaseField("VERSION_ID"); v != "" {
		return id + " " + v
	}
	return id
}

func isUbuntu() bool {
	if strings.EqualFold(osReleaseField("ID"), "ubuntu") {
		return true
	}
	// Mint / Pop!_OS / elementary etc. are Ubuntu-based and use its kernels.
	return strings.Contains(strings.ToLower(osReleaseField("ID_LIKE")), "ubuntu")
}

// debKernelArch maps the Go arch to Debian's kernel meta-package arch suffix.
func debKernelArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "amd64"
	case "arm64":
		return "arm64"
	case "386":
		return "686-pae"
	default:
		return runtime.GOARCH
	}
}

// KernelModulesPackage returns the distro package that provides the PPP/L2TP
// kernel modules missing on minimal/cloud kernels, or "" if we don't know how
// to fix it on this distro (e.g. Arch, whose stock kernel already ships them).
//
//   - Ubuntu: linux-modules-extra-<running-kernel>  (adds modules to the RUNNING
//     kernel — no reboot; kernelPackageFallbacks covers cut-down flavours)
//   - Debian: linux-image-<arch>  (generic kernel; cloud images omit PPP/L2TP so
//     this is a new kernel → reboot + bootloader pin)
//   - Fedora/RHEL/Alma/CentOS: kernel-modules-extra-<running-kernel> (no reboot),
//     else kernel-modules-extra
//   - openSUSE: kernel-default-extra
func KernelModulesPackage() string {
	switch {
	case commandExists("apt-get"):
		if isUbuntu() {
			if r := runningKernel(); r != "" {
				return "linux-modules-extra-" + r
			}
			return "linux-generic"
		}
		// Debian (and non-Ubuntu apt distros): the generic flavour ships the
		// modules the cloud flavour omits.
		return "linux-image-" + debKernelArch()
	case commandExists("dnf"), commandExists("yum"):
		if r := runningKernel(); r != "" {
			return "kernel-modules-extra-" + r
		}
		return "kernel-modules-extra"
	case commandExists("zypper"):
		return "kernel-default-extra"
	default:
		return ""
	}
}

// kernelPackageFallbacks lists packages to try if the primary one can't be
// installed — typically because the exact running-kernel package isn't in the
// repo any more (the box is behind the archive), or the running flavour has no
// -extra split at all (Ubuntu's cut-down "kvm"/minimal images). The fallbacks
// pull a full generic kernel, which means a reboot.
func kernelPackageFallbacks(pkg string) []string {
	switch {
	case strings.HasPrefix(pkg, "linux-modules-extra-"):
		return []string{"linux-generic", "linux-image-generic"}
	case strings.HasPrefix(pkg, "kernel-modules-extra-"):
		return []string{"kernel-modules-extra"}
	case pkg == "kernel-default-extra":
		// openSUSE Leap ships kernel-default-extra (extra modules for the running
		// kernel); Tumbleweed dropped it — the full module set lives in the main
		// kernel-default package, so fall back to that when -extra isn't found.
		return []string{"kernel-default"}
	default:
		return nil
	}
}

// MissingKernelModules returns the required VPN kernel modules that are NOT
// available on the running kernel (not loaded, not built-in, not loadable). This
// is what decides whether a kernel package needs installing — using availability
// rather than "currently loaded" avoids needless kernel installs for built-in
// modules (which have no /sys/module entry).
func (s *CoreService) MissingKernelModules() []string {
	var missing []string
	for _, m := range vpnKernelModules {
		if !moduleAvailable(m) {
			missing = append(missing, m)
		}
	}
	return missing
}

// InstallKernelModules installs the kernel-modules package for this distro,
// tries to load the missing modules against the running kernel, and reports what
// happened. When modules are still missing afterwards they only exist in a
// freshly installed, not-yet-booted kernel — newKernel names that kernel so the
// caller can pin it in the bootloader and prompt a reboot. Must run as root.
func (s *CoreService) InstallKernelModules() (pkg string, stillMissing []string, newKernel string, log string, err error) {
	pkg = KernelModulesPackage()
	if pkg == "" {
		return "", s.MissingKernelModules(), "", "", fmt.Errorf("don't know the kernel package for this distro")
	}
	pm := detectPackageManager()
	if pm == nil {
		return pkg, s.MissingKernelModules(), "", "", fmt.Errorf("no supported package manager")
	}

	// Capture what's missing BEFORE the install. Installing the package makes these
	// modules AVAILABLE but does not LOAD them, so a post-install MissingKernelModules()
	// re-query would no longer list them — and modprobing that (now shorter) list
	// would skip the very modules we just added, leaving them available-but-unloaded
	// (which the status panel shows as a red/not-loaded module — the Fedora l2tp_ppp
	// case, where l2tp_ppp is the one module that ships in kernel-modules-extra).
	wasMissing := s.MissingKernelModules()

	log, err = pm.installPackage(pkg)
	if err != nil {
		for _, alt := range kernelPackageFallbacks(pkg) {
			if out, e := pm.installPackage(alt); e == nil {
				pkg, log, err = alt, log+"\n"+out, nil
				break
			} else {
				log += "\n" + out
			}
		}
	}
	if err != nil {
		return pkg, s.MissingKernelModules(), "", log, err
	}

	// Load the modules that were missing now that the package is installed; modprobe
	// pulls dependencies (l2tp_ppp → l2tp_core, l2tp_netlink). Iterate the pre-install
	// set, not a fresh MissingKernelModules(), so newly-available modules still get
	// loaded rather than silently skipped.
	for _, m := range wasMissing {
		_ = exec.Command("modprobe", m).Run()
	}
	stillMissing = s.MissingKernelModules()

	// Anything still missing only exists in a kernel that isn't booted yet — find
	// which installed kernel actually has the PPP modules so the bootloader can be
	// pointed at it.
	if len(stillMissing) > 0 {
		newKernel = findKernelWithModules("ppp_generic")
	}
	return pkg, stillMissing, newKernel, log, nil
}

// findKernelWithModules returns the newest installed kernel version (other than
// the running one) whose module tree contains the named module, or "" if none.
// "Newest" is by the modules directory's mtime, which reliably points at the
// kernel a fresh install just added.
func findKernelWithModules(moduleBase string) string {
	entries, err := os.ReadDir("/lib/modules")
	if err != nil {
		return ""
	}
	running := runningKernel()
	best := ""
	var bestMtime int64 = -1
	for _, e := range entries {
		if !e.IsDir() || e.Name() == running {
			continue
		}
		ver := e.Name()
		if !kernelHasModule(ver, moduleBase) {
			continue
		}
		info, err := os.Stat("/lib/modules/" + ver)
		if err != nil {
			continue
		}
		if mt := info.ModTime().Unix(); mt > bestMtime {
			bestMtime, best = mt, ver
		}
	}
	return best
}

// kernelHasModule reports whether the given installed kernel provides the named
// module, by scanning its depmod-generated modules.dep (which lists every .ko,
// compressed or not — so a "/ppp_generic.ko" substring matches ppp_generic.ko,
// .ko.xz, .ko.zst, …).
func kernelHasModule(ver, base string) bool {
	data, err := os.ReadFile("/lib/modules/" + ver + "/modules.dep")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "/"+base+".ko")
}
