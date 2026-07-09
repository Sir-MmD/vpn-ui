package service

import (
	"bufio"
	_ "embed"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"sync"
)

// warpCliScript is the bundled Cloudflare warp-cli installer (Sir-MmD/warp-cli).
// It installs the official warp-cli from Cloudflare's repo, registers, and puts
// WARP into SOCKS5 proxy mode on a chosen port. It is run non-interactively here.
//
//go:embed warpcli.sh
var warpCliScript []byte

// ansiRe strips terminal color escapes the script emits, so the log is clean in
// the panel UI.
var ansiRe = regexp.MustCompile("\x1b\\[[0-9;]*m")

// DefaultSocksPort matches warp-cli.sh's default SOCKS5 port.
const DefaultSocksPort = 10808

// The "official WARP-CLI" SOCKS5 feature installs/configures Cloudflare WARP in
// SOCKS5 proxy mode via the bundled warp-cli installer — the alternative to the
// built-in WireGuard WARP outbound. The install runs ~30-90s, so it runs in the
// background through the package-level helpers below (StartWarpSocks /
// WarpSocksState / WarpSocksInstalled) and the modal polls a live log.

// warpSocksRun holds the state of the single in-progress or most-recent warp-cli
// run, so the modal can poll a live log the same way Core Settings polls
// provisioning. Only one warp-cli run happens at a time, so one global suffices.
var warpSocksRun struct {
	mu      sync.Mutex
	running bool
	done    bool
	success bool
	action  string
	log     string
}

// WarpSocksRunState is a snapshot of the background warp-cli run, returned to the
// modal as it polls for live progress.
type WarpSocksRunState struct {
	Running bool   `json:"running"`
	Done    bool   `json:"done"`
	Success bool   `json:"success"`
	Action  string `json:"action"`
	Log     string `json:"log"`
}

// StartWarpSocks launches a warp-cli install/reinstall/uninstall in the
// background and returns true, or returns false without starting a second run if
// one is already in progress. Output streams line-by-line into the run log so a
// concurrent WarpSocksState poll sees partial progress while the ~30-90s install
// is still going. action "install"/"reinstall" runs the installer's --reinstall
// entry point (feeding the chosen SOCKS5 port on stdin); "uninstall" runs
// --uninstall.
func StartWarpSocks(action string, port int) bool {
	warpSocksRun.mu.Lock()
	if warpSocksRun.running {
		warpSocksRun.mu.Unlock()
		return false
	}
	warpSocksRun.running = true
	warpSocksRun.done = false
	warpSocksRun.success = false
	warpSocksRun.action = action
	warpSocksRun.log = ""
	warpSocksRun.mu.Unlock()

	go runWarpSocks(action, port)
	return true
}

// runWarpSocks writes the embedded installer to a temp file and runs it,
// streaming combined stdout+stderr line-by-line (ANSI-stripped) into the run log.
// On exit it flips running=false, done=true and records success.
func runWarpSocks(action string, port int) {
	success := false
	defer func() {
		warpSocksRun.mu.Lock()
		warpSocksRun.running = false
		warpSocksRun.done = true
		warpSocksRun.success = success
		warpSocksRun.mu.Unlock()
	}()

	// Pick the installer flag for the requested action. --reinstall is the one
	// entry point with no interactive branch other than the port prompt, giving a
	// fully unattended install + register + proxy-mode + connect. --uninstall needs
	// no input. The SOCKS5 port is passed via the WARP_SOCKS_PORT env var (not
	// stdin), so no apt/dpkg/gpg step the script runs can consume it and starve the
	// port prompt.
	var flag string
	env := append(os.Environ(), "TERM=dumb", "DEBIAN_FRONTEND=noninteractive")
	switch action {
	case "uninstall":
		flag = "--uninstall"
	default: // "install" / "reinstall"
		flag = "--reinstall"
		if port <= 0 || port > 65535 {
			port = DefaultSocksPort
		}
		env = append(env, "WARP_SOCKS_PORT="+strconv.Itoa(port))
	}

	f, err := os.CreateTemp("", "warp-cli-*.sh")
	if err != nil {
		appendWarpSocksLine("error: " + err.Error())
		return
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(warpCliScript); err != nil {
		f.Close()
		appendWarpSocksLine("error: " + err.Error())
		return
	}
	f.Close()

	cmd := exec.Command("bash", f.Name(), flag)
	// Stdin stays at /dev/null: the port arrives via WARP_SOCKS_PORT and every
	// package step runs non-interactively, so nothing should read stdin. TERM=dumb
	// makes the script's tput color calls resolve to empty strings (no TTY);
	// DEBIAN_FRONTEND keeps apt from blocking on prompts.
	cmd.Env = env

	// Route both streams through one pipe so output is combined and interleaved
	// (exec reuses a single child fd when Stdout == Stderr), then scan it line-by-
	// line into the log so a concurrent poll sees partial output as it arrives.
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw

	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		scanner := bufio.NewScanner(pr)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			appendWarpSocksLine(ansiRe.ReplaceAllString(scanner.Text(), ""))
		}
	}()

	err = cmd.Run()
	pw.Close()
	<-scanDone
	success = err == nil
}

// appendWarpSocksLine appends one output line to the run log under the mutex.
func appendWarpSocksLine(line string) {
	warpSocksRun.mu.Lock()
	warpSocksRun.log += line + "\n"
	warpSocksRun.mu.Unlock()
}

// WarpSocksState returns a snapshot of the current/most-recent warp-cli run: its
// accumulated log plus whether it is running, done and succeeded.
func WarpSocksState() WarpSocksRunState {
	warpSocksRun.mu.Lock()
	defer warpSocksRun.mu.Unlock()
	return WarpSocksRunState{
		Running: warpSocksRun.running,
		Done:    warpSocksRun.done,
		Success: warpSocksRun.success,
		Action:  warpSocksRun.action,
		Log:     warpSocksRun.log,
	}
}

// warpCliPaths are the locations the cloudflare-warp package (and snap) drop the
// warp-cli binary across every supported distro. Checked directly so detection
// works even when the panel process runs with a restricted $PATH (e.g. as a
// systemd unit or a supervised child process) that omits these directories.
var warpCliPaths = []string{
	"/usr/bin/warp-cli",
	"/usr/local/bin/warp-cli",
	"/bin/warp-cli",
	"/snap/bin/warp-cli",
}

// isExecutableFile reports whether path is an existing, non-directory file with
// at least one execute bit set.
func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Mode()&0o111 != 0
}

// WarpSocksInstalled reports whether the official warp-cli is present on the
// host. It first consults $PATH via LookPath, then falls back to the known
// install locations — LookPath alone misses warp-cli when the panel's $PATH
// doesn't include where the package landed it, which wrongly kept the modal on
// the "Install & Connect" view.
func WarpSocksInstalled() bool {
	if _, err := exec.LookPath("warp-cli"); err == nil {
		return true
	}
	for _, p := range warpCliPaths {
		if isExecutableFile(p) {
			return true
		}
	}
	return false
}
