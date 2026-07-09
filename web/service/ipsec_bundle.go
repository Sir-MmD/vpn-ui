package service

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v2/backend"
	"github.com/mhsanaei/3x-ui/v2/logger"
)

// This file lets the panel run its OWN bundled libreswan (pluto) as a supervised
// child process instead of the host's ipsec.service, whenever a relocatable
// libreswan bundle is embedded for this architecture. That bundle is built with
// USE_DH2=true (build/backend/libreswan-bundle.sh), so it offers the MODP1024
// (DH2) group that legacy L2TP/IPsec clients — Windows 7, old MikroTik — need in
// IKEv1, and which no distro libreswan package ships.
//
// When no bundle is embedded (e.g. arm64), usingBundledIpsec() is false and every
// ipsec helper in pkgmgr.go / l2tp.go / core.go falls back to the host package +
// systemd path exactly as before — byte-for-byte unchanged.

const (
	// ipsecConnName is the connection GenerateIPsecConfig writes (conn l2tp-psk).
	ipsecConnName = "l2tp-psk"
	// plutoCtl is the bundled pluto's control socket; DEFAULT_RUNDIR=/run/pluto is
	// compiled into pluto, and addconn/whack talk to this socket.
	plutoCtl = "/run/pluto/pluto.ctl"
	// ipsecProcName is the procMgr key for the pluto child. It matches the "ipsec"
	// core name so the ipsec card's Stop/Logs and the status probe line up.
	ipsecProcName = "ipsec"
)

// usingBundledIpsec reports whether the panel should run its own bundled libreswan
// rather than the host ipsec.service — true whenever a bundle is embedded for this
// arch. Extraction to disk is ensured lazily by ipsecCmd()/startBundledPluto().
func usingBundledIpsec() bool {
	return backend.HasLibreswanBundle()
}

// ipsecAvailable reports whether an `ipsec`/libreswan is usable at all — our
// bundle, or a host install. Replaces the bare commandExists("ipsec") guards,
// which miss the bundle (whose ipsec lives at a fixed path, not on $PATH).
func ipsecAvailable() bool {
	return usingBundledIpsec() || commandExists("ipsec")
}

// ipsecCmd is the `ipsec` command the panel shells out to (for --version,
// checknss, pluto --selftest, auto --add): the bundled wrapper when we ship our
// own libreswan, else the host's ipsec on PATH.
func ipsecCmd() string {
	if usingBundledIpsec() {
		_ = ensureIpsecExtracted()
		return backend.IpsecBundled
	}
	return "ipsec"
}

// ensureIpsecExtracted unpacks the libreswan bundle to its fixed path if it isn't
// already on disk. Idempotent and cheap after the first call.
func ensureIpsecExtracted() error {
	if !usingBundledIpsec() || backend.LibreswanBundleReady() {
		return nil
	}
	return backend.ExtractLibreswanBundle()
}

// bundledIpsecUpdown is the leftupdown command for the bundled pluto: the
// ABSOLUTE path to the bundle's `ipsec` wrapper plus the `_updown` subcommand.
// pluto runs its updown script on every SA up/down; the libreswan default
// `ipsec _updown` relies on `ipsec` being on PATH, but the bundle lives under
// /usr/libexec/vpn-ui and is NOT on the pluto child's PATH — so the default fails
// with "ipsec: not found" (status 127), which aborts the XFRM policy install and
// the IPsec SA never comes up. L2TP then only limps along on its raw fallback, and
// a 2nd concurrent client fails outright. Pointing leftupdown at the absolute path
// (the wrapper fixes PATH/IPSEC_EXECDIR for everything it then runs) resolves it.
func bundledIpsecUpdown() string {
	return backend.LibreswanBundleRoot + "/sbin/ipsec _updown"
}

// ensureIpsecNssDir makes sure the NSS database directory exists before
// `ipsec checknss` runs. The bundled checknss initializes the db files but does
// NOT create their parent dir — host libreswan ships /etc/ipsec.d via its package,
// but our bundle installs nothing under /etc. Without this, checknss fails with
// "destination directory /etc/ipsec.d is missing" and pluto then crash-loops every
// 5s on SEC_ERROR_BAD_DATABASE (NSS init against a missing dir).
func ensureIpsecNssDir() {
	_ = os.MkdirAll(backend.LibreswanNssDir, 0o700)
}

// ensureBundledLibreswan is the provisioning step for the bundled IPsec: extract
// the tree and initialize its NSS database. It does NOT start pluto — that happens
// when L2TP actually loads a connection (RestartServices), which needs the
// generated /etc/ipsec.conf to exist first.
func ensureBundledLibreswan() ProvisionStep {
	if err := ensureIpsecExtracted(); err != nil {
		return ProvisionStep{Name: "libreswan (bundled IPsec)", OK: false,
			Msg: "failed to extract the bundled libreswan: " + err.Error()}
	}
	ensureIpsecNssDir()
	var log strings.Builder
	out, err := exec.Command(backend.IpsecBundled, "checknss").CombinedOutput()
	log.WriteString(string(out))
	if err != nil {
		return ProvisionStep{Name: "libreswan (bundled IPsec)", OK: true, Warn: true,
			Msg: "bundled libreswan extracted; NSS init reported: " + err.Error(), Log: log.String()}
	}
	ver := ""
	if maj, min, ok := libreswanVersion(); ok {
		ver = fmt.Sprintf(" %d.%d", maj, min)
	}
	return ProvisionStep{Name: "libreswan (bundled IPsec)", OK: true,
		Msg: "bundled libreswan" + ver + " ready — ALL_ALGS build (MODP1024 for legacy L2TP clients)",
		Log: log.String()}
}

// startBundledPluto (re)launches the bundled pluto as a panel-managed child and
// loads the L2TP connection into it. Safe to call repeatedly: procMgr.Start
// supersedes any running instance, and the conn is re-added every time so a
// regenerated /etc/ipsec.conf is picked up. Requires /etc/ipsec.conf to exist
// (written by GenerateIPsecConfig) — the caller writes it first.
func startBundledPluto() error {
	if err := ensureIpsecExtracted(); err != nil {
		return err
	}
	// NSS database: the bundled `ipsec checknss` creates the db files under the
	// wrapper's IPSEC_NSSDIR (/etc/ipsec.d) using the bundled certutil — but not the
	// dir itself, so make sure it exists first (else pluto crash-loops on a bad db).
	ensureIpsecNssDir()
	if out, err := exec.Command(backend.IpsecBundled, "checknss").CombinedOutput(); err != nil {
		logger.Warning("bundled ipsec checknss:", err, strings.TrimSpace(string(out)))
	}
	_ = os.MkdirAll("/run/pluto", 0o755)

	// pluto in the foreground so procMgr supervises it and captures its log
	// (--stderrlog routes pluto's log to stderr, which procMgr records).
	args := []string{"--nofork", "--stderrlog", "--config", "/etc/ipsec.conf", "--nssdir", backend.LibreswanNssDir}
	if err := procMgr.Start(ipsecProcName, backend.PlutoBundled, args, nil, ""); err != nil {
		return err
	}

	// Loading a conn needs pluto's control socket, which appears ~1s after start.
	if waitForPath(plutoCtl, 8*time.Second) {
		if out, err := exec.Command(backend.IpsecBundled, "auto", "--add", ipsecConnName).CombinedOutput(); err != nil {
			logger.Warning("bundled ipsec auto --add:", err, strings.TrimSpace(string(out)))
		}
	} else {
		logger.Warning("bundled pluto: control socket never appeared at", plutoCtl)
	}
	return nil
}

// stopBundledPluto stops the panel-managed pluto child (best-effort clean IKE
// shutdown first).
func stopBundledPluto() error {
	_ = exec.Command(backend.IpsecBundled, "whack", "--shutdown").Run()
	return procMgr.Stop(ipsecProcName)
}

// bundledPlutoRunning reports whether the panel-managed pluto child is alive.
func bundledPlutoRunning() bool {
	return procMgr.IsRunning(ipsecProcName)
}

// waitForPath polls until path exists or timeout elapses.
func waitForPath(path string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(150 * time.Millisecond)
	}
}
