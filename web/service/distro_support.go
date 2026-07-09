package service

import (
	"fmt"
	"strings"
)

// supportedDistros is the hard-coded list of distros vpn-ui is actually tested on
// — the test_unit E2E matrix (test_unit/config.toml). Key = /etc/os-release ID,
// value = tested MAJOR versions. A nil value means a rolling release (any version).
// Keep this in sync with the test matrix.
var supportedDistros = map[string][]string{
	"ubuntu":    {"22", "24", "26"},
	"debian":    {"12", "13"},
	"fedora":    {"43", "44"},
	"almalinux": {"8", "9", "10"},
	"rocky":     {"8", "9", "10"},
	"arch":      nil, // rolling release — any version
}

// supportedOrder fixes the display order for the summary (map order is random).
var supportedOrder = []struct{ id, label string }{
	{"ubuntu", "Ubuntu"}, {"debian", "Debian"}, {"fedora", "Fedora"},
	{"almalinux", "AlmaLinux"}, {"rocky", "Rocky"}, {"arch", "Arch"},
}

// distroSupportedBy is the pure matcher (testable without /etc/os-release): given
// an os-release ID and VERSION_ID, report whether the host is on the tested list.
// Matching is ID + MAJOR version (so Alma/Rocky point releases like 9.4 match "9");
// a rolling distro matches any version.
func distroSupportedBy(id, versionID string) (ok bool, reason string) {
	id = strings.ToLower(strings.TrimSpace(id))
	if id == "" {
		return false, "no /etc/os-release ID"
	}
	majors, known := supportedDistros[id]
	if !known {
		return false, fmt.Sprintf("%q is not a tested distro", id)
	}
	if len(majors) == 0 {
		return true, "" // rolling release
	}
	major := strings.SplitN(strings.TrimSpace(versionID), ".", 2)[0]
	for _, m := range majors {
		if m == major {
			return true, ""
		}
	}
	return false, fmt.Sprintf("%s %s is untested (tested: %s)", id, major, strings.Join(majors, "/"))
}

// DistroSupported reports whether the running host is on vpn-ui's tested distro
// list, along with the pretty host name and (when unsupported) a short reason.
func DistroSupported() (ok bool, pretty, reason string) {
	ok, reason = distroSupportedBy(osReleaseField("ID"), osReleaseField("VERSION_ID"))
	return ok, distroPretty(), reason
}

// SupportedDistroSummary is a one-line human list of the tested distros, e.g.
// "Ubuntu 22/24/26, Debian 12/13, Fedora 43/44, AlmaLinux 8/9/10, Rocky 8/9/10, Arch".
func SupportedDistroSummary() string {
	parts := make([]string, 0, len(supportedOrder))
	for _, d := range supportedOrder {
		if v := supportedDistros[d.id]; len(v) > 0 {
			parts = append(parts, d.label+" "+strings.Join(v, "/"))
		} else {
			parts = append(parts, d.label)
		}
	}
	return strings.Join(parts, ", ")
}
