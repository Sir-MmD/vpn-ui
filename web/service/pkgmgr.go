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
			install: []string{"apt-get", "install", "-y"},
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
// the package. Best-effort refresh — an install can still succeed from a warm
// cache if the refresh fails (e.g. one mirror is down).
func (pm *packageManager) installPackage(pkg string) error {
	if len(pm.refresh) > 0 {
		refresh := exec.Command(pm.refresh[0], pm.refresh[1:]...)
		refresh.Env = append(os.Environ(), pm.env...)
		_ = refresh.Run()
	}
	args := append(append([]string{}, pm.install[1:]...), pkg)
	cmd := exec.Command(pm.install[0], args...)
	cmd.Env = append(os.Environ(), pm.env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, lastNonEmptyLine(string(out)))
	}
	return nil
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
// already present. The package is named "libreswan" on every major distro.
// Stock libreswan works for modern clients (Windows/macOS/iOS/Android); MikroTik
// and legacy devices that require the MODP1024 DH group need the ALL_ALGS
// rebuild (handled by setup-vpn-backend.sh), which is out of scope here.
func ensureLibreswan() ProvisionStep {
	if commandExists("ipsec") {
		return ProvisionStep{Name: "libreswan (IPsec)", OK: true, Msg: "already installed"}
	}
	pm := detectPackageManager()
	if pm == nil {
		return ProvisionStep{Name: "libreswan (IPsec)", OK: false,
			Msg: "no supported package manager found — install 'libreswan' manually"}
	}
	if err := pm.installPackage("libreswan"); err != nil {
		return ProvisionStep{Name: "libreswan via " + pm.name, OK: false, Msg: withHint(err.Error(), pm.hint)}
	}
	if !commandExists("ipsec") {
		return ProvisionStep{Name: "libreswan via " + pm.name, OK: false,
			Msg: withHint("install ran but 'ipsec' still not found", pm.hint)}
	}
	return ProvisionStep{Name: "libreswan via " + pm.name, OK: true, Msg: "installed"}
}

func withHint(msg, hint string) string {
	if hint == "" {
		return msg
	}
	return msg + " — " + hint
}

// --------------------------------------------------------------------------- //
//  Kernel modules (installing the full kernel on minimal/cloud images)
// --------------------------------------------------------------------------- //

func readTrim(path string) string {
	b, _ := os.ReadFile(path)
	return strings.TrimSpace(string(b))
}

func runningKernel() string { return readTrim("/proc/sys/kernel/osrelease") }

func isUbuntu() bool {
	return strings.Contains(strings.ToLower(readTrim("/etc/os-release")), "id=ubuntu")
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
// to fix it on this distro (e.g. Arch, or inside a container).
//
//   - Ubuntu: linux-modules-extra-<running-kernel>  (adds modules to the running
//     kernel — usually no reboot needed)
//   - Debian: linux-image-<arch>  (full generic kernel — reboot needed)
//   - Fedora/RHEL: kernel-modules-extra-<running-kernel>, else kernel-modules-extra
//   - openSUSE: kernel-default-extra
func KernelModulesPackage() string {
	switch {
	case commandExists("apt-get"):
		if isUbuntu() {
			if r := runningKernel(); r != "" {
				return "linux-modules-extra-" + r
			}
		}
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

// MissingKernelModules returns the required VPN kernel modules not currently loaded.
func (s *CoreService) MissingKernelModules() []string {
	var missing []string
	for _, m := range vpnKernelModules {
		if !moduleLoaded(m) {
			missing = append(missing, m)
		}
	}
	return missing
}

// InstallKernelModules installs the kernel-modules package for this distro and
// retries loading the missing modules. Returns the package it installed and any
// modules still missing afterward (i.e. a reboot into the new kernel is needed).
// Must be run as root.
func (s *CoreService) InstallKernelModules() (pkg string, stillMissing []string, err error) {
	pkg = KernelModulesPackage()
	if pkg == "" {
		return "", s.MissingKernelModules(), fmt.Errorf("don't know the kernel package for this distro")
	}
	pm := detectPackageManager()
	if pm == nil {
		return pkg, s.MissingKernelModules(), fmt.Errorf("no supported package manager")
	}

	err = pm.installPackage(pkg)
	if err != nil && strings.HasPrefix(pkg, "kernel-modules-extra-") {
		// The exact running-kernel package may not be in the repos (running an
		// older kernel) — fall back to the generic one (installs latest + reboot).
		pkg = "kernel-modules-extra"
		err = pm.installPackage(pkg)
	}
	if err != nil {
		return pkg, s.MissingKernelModules(), err
	}

	// Try to load the modules against the running kernel (works when the package
	// added modules for the current kernel — no reboot needed).
	for _, m := range s.MissingKernelModules() {
		_ = exec.Command("modprobe", m).Run()
	}
	return pkg, s.MissingKernelModules(), nil
}
