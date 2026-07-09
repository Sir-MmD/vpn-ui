package corebundle

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestExtractXray verifies the embedded core (when built by build/core/build.sh)
// extracts to a runnable binary. It is a no-op assertion when no core is bundled
// in this build (a plain checkout without the build step).
func TestExtractXray(t *testing.T) {
	if !HasXray() {
		t.Skip("no core embedded in this build (run build/core/build.sh)")
	}
	dir := t.TempDir()
	path, err := ExtractXray(dir)
	if err != nil {
		t.Fatalf("ExtractXray: %v", err)
	}
	if path == "" {
		t.Fatal("ExtractXray returned empty path despite HasXray")
	}
	if filepath.Base(path) != XrayBinaryName() {
		t.Fatalf("unexpected binary name: %s", path)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat extracted core: %v", err)
	}
	if fi.Mode()&0o111 == 0 {
		t.Fatalf("extracted core is not executable: %v", fi.Mode())
	}
	// Only exec on the native architecture — a cross-built bundle won't run here.
	if runtime.GOARCH == "amd64" {
		out, err := exec.Command(path, "-version").CombinedOutput()
		if err != nil {
			t.Fatalf("core -version failed: %v\n%s", err, out)
		}
		if !strings.Contains(strings.ToLower(string(out)), "xray") {
			t.Fatalf("core -version did not identify as Xray: %s", out)
		}
		t.Logf("bundled core: %s", strings.SplitN(string(out), "\n", 2)[0])
	}
}

// TestExtractGeofiles verifies geo files extract only when missing, so dashboard
// updates survive a restart.
func TestExtractGeofiles(t *testing.T) {
	dir := t.TempDir()
	written, err := ExtractGeofiles(dir)
	if err != nil {
		t.Fatalf("ExtractGeofiles: %v", err)
	}
	if len(written) == 0 {
		t.Skip("no geo files embedded in this build")
	}
	// A second run must NOT overwrite the existing files (write-if-missing).
	sentinel := filepath.Join(dir, "geoip.dat")
	if err := os.WriteFile(sentinel, []byte("USER-EDITED"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ExtractGeofiles(dir); err != nil {
		t.Fatalf("ExtractGeofiles rerun: %v", err)
	}
	got, _ := os.ReadFile(sentinel)
	if string(got) != "USER-EDITED" {
		t.Fatal("ExtractGeofiles clobbered an existing geo file on rerun")
	}
}
