// Package backend bundles the VPN daemon binaries (xl2tpd, and later
// openvpn/libreswan/pppd) directly into the vpn-ui executable via go:embed and
// extracts them at runtime. This lets the panel "bake in" the backend instead
// of installing daemons per-distro through the host package manager.
//
// The bundled binaries are built statically against musl (see
// build/backend/build.sh) so they run on any Linux distribution regardless of
// its libc — including minimal cloud images. Kernel modules are still a host
// concern (they can't be bundled); those are handled by the provisioning step.
package backend

import (
	"embed"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// bundleFS holds the per-architecture daemon binaries. The `all:` prefix keeps
// the embed working when only the .gitkeep placeholder is present (a checkout
// without the prebuilt binaries still compiles — Extract simply becomes a no-op).
//
//go:embed all:bin
var bundleFS embed.FS

// Daemon describes one bundled daemon.
type Daemon struct {
	Name string // binary file name, e.g. "xl2tpd"
}

// Daemons is the manifest of bundled daemons (extended as more are added).
var Daemons = []Daemon{
	{Name: "xl2tpd"},
	{Name: "xl2tpd-control"},
	{Name: "openvpn"},
	{Name: "pptpd"},
	{Name: "pptpctrl"},
}

// PptpCtrlLink is the fixed path pptpd was compiled to exec pptpctrl from
// (--sbindir sentinel). Provisioning symlinks it to the extracted pptpctrl so
// the bundle works regardless of where vpn-ui is installed.
const PptpCtrlLink = "/usr/libexec/vpn-ui/pptpctrl"

// archDir is the embedded sub-directory for the running architecture.
func archDir() string { return "bin/" + runtime.GOARCH }

// Available reports whether a daemon bundle is embedded for this architecture.
func Available() bool {
	entries, err := bundleFS.ReadDir(archDir())
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() {
			return true
		}
	}
	return false
}

// BinDir is the absolute directory where daemons are extracted — next to the
// vpn-ui executable, so it adapts to any install location (/usr/local/vpn-ui,
// /usr/lib/vpn-ui, …).
func BinDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "/usr/local/vpn-ui/backend/bin"
	}
	return filepath.Join(filepath.Dir(exe), "backend", "bin")
}

// DaemonPath returns the extracted path of a bundled daemon if it exists on
// disk, otherwise "".
func DaemonPath(name string) string {
	p := filepath.Join(BinDir(), name)
	if st, err := os.Stat(p); err == nil && !st.IsDir() {
		return p
	}
	return ""
}

// Extract writes all bundled daemon binaries for this architecture into BinDir()
// with 0755 permissions. It is idempotent (overwrites existing files) and a
// no-op when no bundle is embedded. Returns the list of files written.
func Extract() ([]string, error) {
	if !Available() {
		return nil, nil
	}
	dir := BinDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	entries, err := bundleFS.ReadDir(archDir())
	if err != nil {
		return nil, err
	}
	var written []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		// Archive bundles (e.g. the pppd tree) are extracted separately, not
		// dropped as a flat file into BinDir.
		if strings.HasSuffix(e.Name(), ".tgz") {
			continue
		}
		data, err := bundleFS.ReadFile(archDir() + "/" + e.Name())
		if err != nil {
			return written, err
		}
		dest := filepath.Join(dir, e.Name())
		if err := writeExecutable(dest, data); err != nil {
			return written, err
		}
		written = append(written, dest)
	}
	return written, nil
}

// writeExecutable writes an executable to dest via a temp file + atomic rename.
// A plain overwrite of a daemon that's currently running fails with ETXTBSY
// ("text file busy") because the kernel keeps the running binary's file mapped.
// Rename swaps the directory entry to a fresh inode instead — the running
// process keeps executing the old inode, and the next start picks up the new one.
func writeExecutable(dest string, data []byte) error {
	tmp := dest + ".new"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
