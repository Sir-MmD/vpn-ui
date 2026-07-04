package service

import "strings"

import "testing"

func TestSanitizeServiceName(t *testing.T) {
	cases := map[string]string{
		"vpn-ui":              "vpn-ui",
		"  my-panel  ":        "my-panel",
		"my-panel.service":    "my-panel", // .service suffix stripped
		"x_ui@1":              "x_ui@1",
		"":                    "vpn-ui", // empty falls back
		"../../etc/passwd":    "....etcpasswd",
		"a/b/c":               "abc",
		"na me/../evil":       "name..evil",
		"foo;rm -rf /":        "foorm-rf",
		"vpn-ui.service.conf": "vpn-ui.service.conf", // only a TRAILING .service is stripped
	}
	for in, want := range cases {
		if got := sanitizeServiceName(in); got != want {
			t.Errorf("sanitizeServiceName(%q) = %q, want %q", in, got, want)
		}
		// Hard guarantee: the result can never contain a path separator, so
		// unitPath() can't escape /etc/systemd/system.
		if strings.ContainsAny(sanitizeServiceName(in), `/\`) {
			t.Errorf("sanitizeServiceName(%q) leaked a path separator", in)
		}
	}
}

func TestDefaultUnitShape(t *testing.T) {
	u := DefaultUnit("vpn-ui")
	for _, must := range []string{"[Unit]", "[Service]", "ExecStart=", "WantedBy=multi-user.target", "Description=vpn-ui"} {
		if !strings.Contains(u, must) {
			t.Errorf("DefaultUnit missing %q", must)
		}
	}
}
