package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// SystemdService installs and controls a systemd unit for the panel itself, so
// the panel can run as a managed service (enabled on boot, auto-restarted)
// instead of a bare background process. It's driven from Panel Settings.
type SystemdService struct{}

// SystemdState is the current state of the panel's systemd unit, for the UI.
type SystemdState struct {
	Available   bool   `json:"available"`   // systemctl present on the host
	Name        string `json:"name"`        // service name (without .service)
	Installed   bool   `json:"installed"`   // unit file exists
	Enabled     bool   `json:"enabled"`     // starts on boot
	Active      bool   `json:"active"`      // currently running
	Unit        string `json:"unit"`        // unit file content (existing on disk, or generated default)
	DefaultUnit string `json:"defaultUnit"` // freshly generated default, for the "load default" button
	ExePath     string `json:"exePath"`     // panel binary path, for reference
}

var serviceNameRe = regexp.MustCompile(`[^a-zA-Z0-9._@-]`)

// sanitizeServiceName strips anything that isn't a safe systemd unit-name
// character so the name can't escape /etc/systemd/system. Falls back to "vpn-ui".
func sanitizeServiceName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, ".service")
	name = serviceNameRe.ReplaceAllString(name, "")
	if name == "" {
		return "vpn-ui"
	}
	return name
}

func unitPath(name string) string {
	return "/etc/systemd/system/" + name + ".service"
}

func systemctl(args ...string) (string, error) {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// GetServiceName returns the configured panel service name (default "vpn-ui").
func (s *SystemdService) GetServiceName() string {
	var ss SettingService
	name, err := ss.GetSystemdServiceName()
	if err != nil || strings.TrimSpace(name) == "" {
		return "vpn-ui"
	}
	return sanitizeServiceName(name)
}

// DefaultUnit builds a default systemd unit for the running panel binary. The
// WorkingDirectory is the binary's own directory so its relative paths (bin/,
// backend/bin) and the next-to-binary database resolve the same as a manual run.
func DefaultUnit(name string) string {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		exe = "/usr/local/vpn-ui/vpn-ui"
	}
	return fmt.Sprintf(`[Unit]
Description=%s panel service
After=network.target network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=%s
ExecStart=%s
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`, name, filepath.Dir(exe), exe)
}

// ServiceState reports the current unit state, returning the on-disk unit content
// when installed or a generated default otherwise (so the editor is pre-filled).
func (s *SystemdService) ServiceState() SystemdState {
	name := s.GetServiceName()
	exe, _ := os.Executable()
	st := SystemdState{
		Available:   commandExists("systemctl"),
		Name:        name,
		ExePath:     exe,
		DefaultUnit: DefaultUnit(name),
	}
	if data, err := os.ReadFile(unitPath(name)); err == nil {
		st.Installed = true
		st.Unit = string(data)
	} else {
		st.Unit = DefaultUnit(name)
	}
	if st.Available {
		switch out, _ := systemctl("is-enabled", name); out {
		case "enabled", "enabled-runtime", "static", "alias":
			st.Enabled = true
		}
		st.Active = systemctlActive(name)
	}
	return st
}

// ServiceLog returns a live-ish status view of the panel's unit: `systemctl
// status` (state, recent journal tail) followed by the last journal lines, so
// the settings page can show what the service is doing right now. Best-effort —
// returns a friendly message when systemd or the unit isn't there.
func (s *SystemdService) ServiceLog() string {
	name := s.GetServiceName()
	if !commandExists("systemctl") {
		return "systemctl not found — this host doesn't use systemd."
	}
	var b strings.Builder
	if out, _ := systemctl("status", name, "--no-pager", "-n", "40"); out != "" {
		b.WriteString(out)
	}
	if commandExists("journalctl") {
		jout, _ := exec.Command("journalctl", "-u", name, "--no-pager", "-n", "80", "-o", "short-iso").CombinedOutput()
		if t := strings.TrimSpace(string(jout)); t != "" {
			b.WriteString("\n\n──── journal ────\n")
			b.WriteString(t)
		}
	}
	out := strings.TrimSpace(b.String())
	if out == "" {
		return "No status yet — the service '" + name + "' isn't installed or hasn't run. Apply to install it."
	}
	return out
}

// SaveServiceRequest is the payload from the Systemd Service settings panel.
// It's posted form-urlencoded (the panel's axios interceptor Qs.stringify's all
// request bodies), so both form and json tags are declared for c.ShouldBind.
type SaveServiceRequest struct {
	Name   string `json:"name" form:"name"`
	Unit   string `json:"unit" form:"unit"`
	Enable bool   `json:"enable" form:"enable"` // start on boot
	Start  bool   `json:"start" form:"start"`   // run now
}

// SaveService writes/updates the unit file, reloads systemd, and applies the
// enable (start-on-boot) and start (run-now) toggles. When the service name
// changes it tears down the previously-named unit first. Must run as root.
func (s *SystemdService) SaveService(req SaveServiceRequest) error {
	if !commandExists("systemctl") {
		return fmt.Errorf("systemctl not found — this host doesn't use systemd")
	}
	name := sanitizeServiceName(req.Name)
	unit := req.Unit
	if strings.TrimSpace(unit) == "" {
		unit = DefaultUnit(name)
	}

	var ss SettingService
	// If the operator renamed the service, remove the old unit so it isn't orphaned.
	if oldName := s.GetServiceName(); oldName != "" && oldName != name {
		_, _ = systemctl("disable", "--now", oldName)
		_ = os.Remove(unitPath(oldName))
	}

	if err := os.WriteFile(unitPath(name), []byte(unit), 0o644); err != nil {
		return fmt.Errorf("write unit file: %w", err)
	}
	if err := ss.SetSystemdServiceName(name); err != nil {
		return err
	}
	if out, err := systemctl("daemon-reload"); err != nil {
		return fmt.Errorf("daemon-reload failed: %v: %s", err, out)
	}

	if req.Enable {
		if out, err := systemctl("enable", name); err != nil {
			return fmt.Errorf("enable failed: %v: %s", err, out)
		}
	} else {
		_, _ = systemctl("disable", name)
	}

	if req.Start {
		if out, err := systemctl("restart", name); err != nil {
			return fmt.Errorf("start failed: %v: %s", err, out)
		}
	} else {
		_, _ = systemctl("stop", name)
	}
	return nil
}

// RemoveService stops, disables and removes the named panel unit, then reloads
// systemd. Best-effort: it attempts every step regardless of individual
// failures (the unit may be half-installed or already gone) and returns the
// unit-file removal error only when it's something other than "not found".
// This is the standalone teardown counterpart to SaveService and is used by the
// `--uninstall` path. Safe to call for a unit that was started outside this
// process (`disable --now` stops that unit's own PID, not the caller).
func (s *SystemdService) RemoveService(name string) error {
	name = sanitizeServiceName(name)
	if commandExists("systemctl") {
		_, _ = systemctl("disable", "--now", name)
	}
	err := os.Remove(unitPath(name))
	if commandExists("systemctl") {
		_, _ = systemctl("daemon-reload")
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
