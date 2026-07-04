package backend

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
)

// The pppd relocatable bundle. pppd loads its radius plugin (and OpenSSL loads
// its legacy provider for MS-CHAP/MPPE) via dlopen, so pppd can't be a single
// static binary like the others. Instead it ships as a small tree — the
// musl-linked pppd + radius.so + OpenSSL legacy provider + their .so deps + the
// musl loader — patchelf'd to a FIXED path so its ELF interpreter/rpath resolve
// regardless of the host distro. That fixed path must match the build.
const (
	PppdBundleRoot = "/usr/libexec/vpn-ui"
	PppdBundled    = PppdBundleRoot + "/sbin/pppd"
	PppdSystem     = "/usr/sbin/pppd"
	OpenSSLModules = PppdBundleRoot + "/lib/ossl-modules"
)

func pppdBundleName() string { return archDir() + "/pppd-bundle.tgz" }

// HasPppdBundle reports whether a relocatable pppd bundle is embedded for this
// architecture.
func HasPppdBundle() bool {
	f, err := bundleFS.Open(pppdBundleName())
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// UsingBundledPppd reports whether the daemons should use the bundled pppd —
// true only when the bundle is present AND the host has no system pppd of its
// own (we never shadow a distro pppd, whose OpenSSL providers differ).
func UsingBundledPppd() bool {
	if !HasPppdBundle() {
		return false
	}
	// A real system pppd (not our symlink to the bundle) means: use the system one.
	if dest, err := os.Readlink(PppdSystem); err == nil {
		return dest == PppdBundled // our own symlink → still "bundled"
	}
	_, err := os.Stat(PppdSystem)
	return err != nil // no system pppd → use the bundle
}

// ExtractPppdBundle untars the embedded pppd bundle to the filesystem root
// (its entries are rooted at usr/libexec/vpn-ui). Idempotent; no-op if absent.
func ExtractPppdBundle() error {
	if !HasPppdBundle() {
		return nil
	}
	data, err := bundleFS.ReadFile(pppdBundleName())
	if err != nil {
		return err
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		target := filepath.Join("/", filepath.Clean("/"+hdr.Name))
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeSymlink:
			_ = os.MkdirAll(filepath.Dir(target), 0o755)
			_ = os.Remove(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(hdr.Mode)&0o777)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				_ = f.Close()
				return err
			}
			_ = f.Close()
		}
	}
	return nil
}

// LinkSystemPppd points /usr/sbin/pppd at the bundled pppd when the host has no
// pppd of its own, so xl2tpd (which execs the hard-coded /usr/sbin/pppd) uses
// the bundle. No-op if a system pppd already exists.
func LinkSystemPppd() error {
	if !HasPppdBundle() {
		return nil
	}
	if _, err := os.Lstat(PppdSystem); err == nil {
		return nil // system pppd or our prior link already present
	}
	if _, err := os.Stat(PppdBundled); err != nil {
		return nil
	}
	_ = os.MkdirAll(filepath.Dir(PppdSystem), 0o755)
	return os.Symlink(PppdBundled, PppdSystem)
}

// PppdPluginDir is pppd's compiled-in plugin directory. A bare `plugin radius.so`
// option is resolved by pppd relative to this path, so the bundled plugins must
// be reachable here.
const PppdPluginDir = "/usr/lib/pppd"

// LinkPluginDir points /usr/lib/pppd at the bundle's plugin tree when the host
// has no pppd of its own, so the bundled pppd resolves `plugin radius.so` /
// `plugin pppol2tp.so` to the embedded plugins. No-op if the host already has a
// plugin dir (host ppp installed) or when there's no bundle.
func LinkPluginDir() error {
	if !HasPppdBundle() {
		return nil
	}
	if _, err := os.Lstat(PppdPluginDir); err == nil {
		return nil // host ppp's plugin dir (or our prior link) already present
	}
	src := PppdBundleRoot + "/lib/pppd"
	if _, err := os.Stat(src); err != nil {
		return nil
	}
	_ = os.MkdirAll(filepath.Dir(PppdPluginDir), 0o755)
	return os.Symlink(src, PppdPluginDir)
}
