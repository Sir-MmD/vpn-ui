package service

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
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
			hint:    "openSUSE ships strongSwan, not libreswan — add the 'network:vpn' OBS repo for a libreswan package, or use strongSwan",
		}
	case commandExists("pacman"):
		return &packageManager{
			name:    "pacman",
			refresh: []string{"pacman", "-Sy", "--noconfirm"},
			install: []string{"pacman", "-S", "--needed", "--noconfirm"},
			hint:    "libreswan is not in Arch's official repos — install it from the AUR (e.g. 'yay -S libreswan')",
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
		// A hint means libreswan isn't in this distro's default repos (Arch = AUR
		// only, openSUSE = strongSwan). That's a soft limitation, not a broken
		// setup: L2TP/IPsec is unavailable but raw-L2TP/PPTP/OpenVPN still work, so
		// report it as a Warn rather than a red failure.
		if err != nil {
			if pm.hint != "" {
				return ProvisionStep{Name: "libreswan via " + pm.name, OK: true, Warn: true,
					Msg: "IPsec unavailable — " + pm.hint + " (PPTP/OpenVPN/raw-L2TP still work)", Log: log.String()}
			}
			return ProvisionStep{Name: "libreswan via " + pm.name, OK: false, Msg: err.Error(), Log: log.String()}
		}
		if !commandExists("ipsec") {
			return ProvisionStep{Name: "libreswan via " + pm.name, OK: false,
				Msg: withHint("install ran but 'ipsec' still not found", pm.hint), Log: log.String()}
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
	return ProvisionStep{Name: "libreswan (IPsec)", OK: true, Warn: true,
		Msg: "installed; NSS initialized; ipsec not yet active (check `systemctl status ipsec`)", Log: log.String()}
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

	// The package may have added modules for the RUNNING kernel (no reboot). Load
	// them now; modprobe pulls dependencies (l2tp_ppp → l2tp_core, l2tp_netlink).
	for _, m := range s.MissingKernelModules() {
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
