package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// --------------------------------------------------------------------------- //
//  Bootloader: make a freshly installed kernel actually boot
// --------------------------------------------------------------------------- //
//
// When the VPN's PPP/L2TP modules only exist in a full kernel that provisioning
// had to install (e.g. a Debian/Ubuntu cloud image whose stock kernel omits
// them), installing that kernel isn't enough: the module-less kernel can stay
// the boot default. On Debian this is the common case — the generic and cloud
// flavours share a version, and GRUB's tie-break sorts the cloud flavour later,
// so it wins. So after installing the kernel we pin the new one as the default.
//
// The pin is non-destructive: the previous kernel stays installed as a fallback,
// so if the new kernel somehow fails to boot the machine is still recoverable.

// ensureBootloaderBootsKernel makes the given kernel version the persistent boot
// default across the bootloaders these distros use (GRUB2 on Debian/Ubuntu and
// BIOS Fedora/RHEL; grubby on Fedora/RHEL; systemd-boot on UEFI setups).
func ensureBootloaderBootsKernel(version string) (string, error) {
	if version == "" {
		return "", fmt.Errorf("no installed kernel with the modules was found to boot")
	}
	switch {
	// grubby (Fedora/RHEL/Alma/CentOS) is the simplest and most reliable when
	// present, so prefer it over hand-editing grub.cfg.
	case commandExists("grubby"):
		return pinGrubbyKernel(version)
	case grubInstalled():
		return pinGrubKernel(version)
	case commandExists("bootctl"):
		return pinSystemdBootKernel(version)
	default:
		return "", fmt.Errorf("couldn't detect the bootloader — after rebooting, pick the %q kernel from the boot menu", version)
	}
}

func grubInstalled() bool {
	return commandExists("update-grub") || commandExists("grub-mkconfig") ||
		commandExists("grub2-mkconfig") || fileExists("/etc/default/grub")
}

// grubCfgPath returns the active grub.cfg, checking the common BIOS and UEFI
// locations across Debian/Ubuntu and the RHEL family.
func grubCfgPath() string {
	candidates := []string{
		"/boot/grub/grub.cfg",
		"/boot/grub2/grub.cfg",
		"/boot/efi/EFI/debian/grub.cfg",
		"/boot/efi/EFI/ubuntu/grub.cfg",
		"/boot/efi/EFI/fedora/grub.cfg",
		"/boot/efi/EFI/centos/grub.cfg",
		"/boot/efi/EFI/almalinux/grub.cfg",
		"/boot/efi/EFI/redhat/grub.cfg",
	}
	for _, p := range candidates {
		if fileExists(p) {
			return p
		}
	}
	return ""
}

// pinGrubKernel pins version as the persistent GRUB default by switching to
// GRUB_DEFAULT=saved, regenerating the config, and pointing the saved entry at
// the matching (non-recovery) menuentry.
func pinGrubKernel(version string) (string, error) {
	if err := setGrubDefaultSaved(); err != nil {
		return "", err
	}
	if err := regenerateGrub(); err != nil {
		return "", err
	}
	id, err := findGrubEntryID(version)
	if err != nil {
		return "", fmt.Errorf("kernel %s installed but its GRUB entry wasn't found (%v) — pick it under 'Advanced options' at boot", version, err)
	}
	setter := "grub-set-default"
	if !commandExists(setter) {
		setter = "grub2-set-default"
	}
	if out, err := exec.Command(setter, id).CombinedOutput(); err != nil {
		return "", fmt.Errorf("%s %q: %v: %s", setter, id, err, lastNonEmptyLine(string(out)))
	}
	return "pinned GRUB to " + version + " (previous kernel kept as a fallback)", nil
}

// setGrubDefaultSaved sets GRUB_DEFAULT=saved in /etc/default/grub so that
// grub-set-default takes effect, leaving the rest of the file untouched. A
// missing file is not fatal — grub2-set-default still works via grubenv.
func setGrubDefaultSaved() error {
	const path = "/etc/default/grub"
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := strings.Split(string(data), "\n")
	found := false
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "GRUB_DEFAULT=") {
			lines[i] = "GRUB_DEFAULT=saved"
			found = true
		}
	}
	if !found {
		lines = append(lines, "GRUB_DEFAULT=saved")
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644)
}

// regenerateGrub rebuilds grub.cfg using whichever generator the distro ships.
func regenerateGrub() error {
	if commandExists("update-grub") {
		if out, err := exec.Command("update-grub").CombinedOutput(); err != nil {
			return fmt.Errorf("update-grub: %v: %s", err, lastNonEmptyLine(string(out)))
		}
		return nil
	}
	cfg := grubCfgPath()
	if cfg == "" {
		cfg = "/boot/grub2/grub.cfg"
	}
	mk := "grub-mkconfig"
	if !commandExists(mk) {
		mk = "grub2-mkconfig"
	}
	if out, err := exec.Command(mk, "-o", cfg).CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v: %s", mk, err, lastNonEmptyLine(string(out)))
	}
	return nil
}

var (
	grubKeywordRe = regexp.MustCompile(`^\s*(menuentry|submenu)\s+'((?:[^'\\]|\\.)*)'`)
	grubEntryIDRe = regexp.MustCompile(`\$menuentry_id_option\s+'([^']+)'`)
)

// findGrubEntryID returns the grub-set-default identifier for the normal (non-
// recovery) boot entry of the given kernel version. Debian/Ubuntu list versioned
// entries inside a single "Advanced options" submenu, so the id is
// "<submenu-id>>​<entry-id>"; when there is no submenu it is just the entry id.
// The top-level simple entry has no version in its title, so matching on the
// version string reliably selects the submenu entry.
func findGrubEntryID(version string) (string, error) {
	cfg := grubCfgPath()
	if cfg == "" {
		return "", fmt.Errorf("grub.cfg not found")
	}
	data, err := os.ReadFile(cfg)
	if err != nil {
		return "", err
	}
	return parseGrubEntryID(string(data), version)
}

// parseGrubEntryID is the pure parser behind findGrubEntryID (split out so it can
// be unit-tested without a grub.cfg on disk).
func parseGrubEntryID(cfg, version string) (string, error) {
	lines := strings.Split(cfg, "\n")

	entryID := func(line, title string) string {
		if m := grubEntryIDRe.FindStringSubmatch(line); m != nil {
			return m[1]
		}
		return title // older GRUB without $menuentry_id_option: default by title
	}

	submenuID := ""
	for _, line := range lines {
		m := grubKeywordRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		keyword, title := m[1], m[2]
		if keyword == "submenu" {
			if submenuID == "" {
				submenuID = entryID(line, title)
			}
			continue
		}
		if !strings.Contains(title, version) || strings.Contains(strings.ToLower(title), "recovery") {
			continue
		}
		id := entryID(line, title)
		if submenuID != "" {
			return submenuID + ">" + id, nil
		}
		return id, nil
	}
	return "", fmt.Errorf("no non-recovery entry mentions %q", version)
}

// pinGrubbyKernel sets the default kernel via grubby (Fedora/RHEL/Alma/CentOS),
// which handles BIOS GRUB2, UEFI GRUB2 and BLS transparently.
func pinGrubbyKernel(version string) (string, error) {
	vmlinuz := "/boot/vmlinuz-" + version
	if !fileExists(vmlinuz) {
		if g := firstGlobMatch("/boot/vmlinuz-" + version + "*"); g != "" {
			vmlinuz = g
		}
	}
	if !fileExists(vmlinuz) {
		return "", fmt.Errorf("vmlinuz for %s not found under /boot", version)
	}
	if out, err := exec.Command("grubby", "--set-default", vmlinuz).CombinedOutput(); err != nil {
		return "", fmt.Errorf("grubby --set-default %s: %v: %s", vmlinuz, err, lastNonEmptyLine(string(out)))
	}
	return "set default kernel to " + version + " via grubby", nil
}

// pinSystemdBootKernel points systemd-boot at the loader entry for version.
func pinSystemdBootKernel(version string) (string, error) {
	for _, dir := range []string{"/boot/loader/entries", "/efi/loader/entries", "/boot/efi/loader/entries"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
				continue
			}
			body, _ := os.ReadFile(filepath.Join(dir, e.Name()))
			if !strings.Contains(string(body), version) {
				continue
			}
			if out, err := exec.Command("bootctl", "set-default", e.Name()).CombinedOutput(); err != nil {
				return "", fmt.Errorf("bootctl set-default %s: %v: %s", e.Name(), err, lastNonEmptyLine(string(out)))
			}
			return "set systemd-boot default to " + e.Name(), nil
		}
	}
	return "", fmt.Errorf("no systemd-boot entry references %s", version)
}

func firstGlobMatch(pattern string) string {
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return ""
	}
	return matches[0]
}
