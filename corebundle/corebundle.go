// Package corebundle bakes the project's pinned Xray core binary and the base
// geo data files (geoip.dat / geosite.dat) into the panel executable via
// go:embed and extracts them at runtime.
//
// The panel ships a SPECIFIC patched Xray-core fork (Sir-MmD/Xray-core, which
// fixes the Shadowsocks per-user `method` fallback). To guarantee that exact
// core is always the one that runs, ExtractXray overwrites the on-disk core
// binary on every startup, and the panel forbids switching/updating the core
// version from the dashboard (see ServerService.UpdateXray).
//
// The embedded assets live under core/ and are gitignored (only a .gitkeep is
// tracked) — they are produced at build time by build/core/build.sh, exactly
// like the daemon bundle in the `backend` package. A checkout without them still
// compiles; extraction simply becomes a no-op and the panel falls back to
// whatever core binary is already on disk.
//
// Layout consumed by the go:embed below:
//
//	core/<goarch>/xray      the pinned core binary for that architecture
//	core/geoip.dat          base geo data (architecture-independent)
//	core/geosite.dat
package corebundle

import (
	"embed"
	"os"
	"path/filepath"
	"runtime"
)

// bundleFS holds the pinned core binary + base geo files. The `all:` prefix
// keeps the embed working when only the .gitkeep placeholder is present.
//
//go:embed all:core
var bundleFS embed.FS

// geoFiles are the base geo data files shipped as a first-run fallback. Updating
// them from the dashboard is allowed, so ExtractGeofiles only writes them when
// missing — it never clobbers a dashboard-updated copy.
var geoFiles = []string{"geoip.dat", "geosite.dat"}

// XrayBinaryName is the on-disk core binary name the panel launches. It matches
// the name xray/process.go builds ("xray-<goos>-<goarch>").
func XrayBinaryName() string {
	return "xray-" + runtime.GOOS + "-" + runtime.GOARCH
}

// archXrayPath is the embedded path of the core binary for this architecture.
func archXrayPath() string { return "core/" + runtime.GOARCH + "/xray" }

// HasXray reports whether a core binary is embedded for this architecture.
func HasXray() bool {
	f, err := bundleFS.Open(archXrayPath())
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// ExtractXray writes the bundled core binary into binDir as XrayBinaryName(),
// overwriting any existing file so the pinned fork is always the core that runs.
// It is a no-op (returns "", nil) when no core is embedded for this arch.
// Returns the written path.
func ExtractXray(binDir string) (string, error) {
	if !HasXray() {
		return "", nil
	}
	data, err := bundleFS.ReadFile(archXrayPath())
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return "", err
	}
	dest := filepath.Join(binDir, XrayBinaryName())
	if err := writeAtomically(dest, data, 0o755); err != nil {
		return "", err
	}
	return dest, nil
}

// ExtractGeofiles writes each bundled base geo file into binDir ONLY IF it is
// missing, so dashboard updates to geoip.dat/geosite.dat survive a restart.
// Files not embedded in this build are silently skipped. Returns the paths
// actually written.
func ExtractGeofiles(binDir string) ([]string, error) {
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return nil, err
	}
	var written []string
	for _, name := range geoFiles {
		data, err := bundleFS.ReadFile("core/" + name)
		if err != nil {
			continue // not bundled in this build
		}
		dest := filepath.Join(binDir, name)
		if _, err := os.Stat(dest); err == nil {
			continue // already present — keep the existing (possibly updated) copy
		}
		if err := writeAtomically(dest, data, 0o644); err != nil {
			return written, err
		}
		written = append(written, dest)
	}
	return written, nil
}

// writeAtomically writes data to dest via a temp file + rename. The rename swaps
// the directory entry to a fresh inode, which avoids ETXTBSY ("text file busy")
// when overwriting a core binary that is currently mapped by a running process.
func writeAtomically(dest string, data []byte, mode os.FileMode) error {
	tmp := dest + ".new"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
