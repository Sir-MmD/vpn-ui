package backend

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
)

// The libreswan (IPsec) relocatable bundle.
//
// Why bundle it at all: distro libreswan packages are built with USE_DH2=false,
// so they omit the MODP1024 (DH group 2) modular-exponentiation group. Windows 7
// and other legacy L2TP/IPsec clients propose DH2 in IKEv1 main mode, so against
// a stock server their phase-1 negotiation finds no common group and fails. The
// only way to offer MODP1024 is a libreswan built with USE_DH2=true — a
// build-time flag with no ipsec.conf/runtime equivalent. We therefore ship our
// own USE_DH2=true build (see build/backend/libreswan-bundle.sh).
//
// Why a relocatable tree (not one static binary): pluto links NSS (which itself
// dlopens libsoftokn3/libfreebl3 at runtime), libnspr, libevent and gmp — NSS in
// particular does not static-link cleanly. So, exactly like the pppd bundle, we
// ship pluto + its helper programs (whack, addconn, …) + the `ipsec` wrapper +
// every .so dependency + the NSS PKCS#11 modules + the musl loader in a tree
// rooted at a FIXED path, and drive it through launcher wrappers that invoke the
// bundled musl loader with --library-path. That makes it run on any host libc.
//
// The tree is tarred to backend/bin/<goarch>/libreswan-bundle.tgz and consumed
// here. The fixed paths below are the contract the build script must honor.
const (
	// LibreswanBundleRoot is where the tree unpacks. Kept under the shared
	// /usr/libexec/vpn-ui prefix but in its own subdir so it never collides with
	// the pppd bundle's sbin/ and lib/.
	LibreswanBundleRoot = "/usr/libexec/vpn-ui/libreswan"

	// IpsecBundled is the launcher for the libreswan `ipsec` command wrapper. It
	// sets the IPSEC_* dir overrides + the musl loader path, then execs the real
	// wrapper, so `ipsec pluto --selftest`, `ipsec checknss`, `ipsec auto --add`,
	// `ipsec whack …` and `ipsec --version` all resolve inside the bundle.
	IpsecBundled = LibreswanBundleRoot + "/sbin/ipsec"

	// PlutoBundled is the launcher for the pluto daemon itself, run directly as a
	// panel-managed child process (procmgr) instead of through systemd.
	PlutoBundled = LibreswanBundleRoot + "/sbin/pluto"

	// LibreswanNssDir is the NSS database directory the bundled pluto uses. It is
	// the libreswan default so generated ipsec.conf/ipsec.secrets paths are
	// unchanged; `ipsec checknss` (bundled) initializes it.
	LibreswanNssDir = "/etc/ipsec.d"
)

func libreswanBundleName() string { return archDir() + "/libreswan-bundle.tgz" }

// HasLibreswanBundle reports whether a relocatable libreswan bundle is embedded
// for this architecture.
func HasLibreswanBundle() bool {
	f, err := bundleFS.Open(libreswanBundleName())
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// LibreswanBundleReady reports whether the bundle is embedded AND already
// extracted (the launcher exists on disk), i.e. the panel can run its own pluto.
func LibreswanBundleReady() bool {
	if !HasLibreswanBundle() {
		return false
	}
	st, err := os.Stat(IpsecBundled)
	return err == nil && !st.IsDir()
}

// ExtractLibreswanBundle untars the embedded libreswan bundle to the filesystem
// root (its entries are rooted at usr/libexec/vpn-ui/libreswan). Idempotent;
// no-op when no bundle is embedded for this architecture.
func ExtractLibreswanBundle() error {
	if !HasLibreswanBundle() {
		return nil
	}
	data, err := bundleFS.ReadFile(libreswanBundleName())
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
