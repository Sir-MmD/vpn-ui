package service

import "testing"

// A realistic Debian/Ubuntu grub.cfg: one top-level "simple" entry (no version
// in its title) plus an "Advanced options" submenu holding the versioned
// entries, including a recovery variant and an older cloud kernel.
const sampleGrubCfg = `
menuentry 'Debian GNU/Linux' --class debian --class gnu-linux --class gnu --class os $menuentry_id_option 'gnulinux-simple-abcd-uuid' {
	linux /boot/vmlinuz-6.12.12-amd64 root=UUID=abcd ro quiet
}
submenu 'Advanced options for Debian GNU/Linux' $menuentry_id_option 'gnulinux-advanced-abcd-uuid' {
	menuentry 'Debian GNU/Linux, with Linux 6.12.12-amd64' --class debian $menuentry_id_option 'gnulinux-6.12.12-amd64-advanced-abcd-uuid' {
		linux /boot/vmlinuz-6.12.12-amd64 root=UUID=abcd ro quiet
	}
	menuentry 'Debian GNU/Linux, with Linux 6.12.12-amd64 (recovery mode)' --class debian $menuentry_id_option 'gnulinux-6.12.12-amd64-recovery-abcd-uuid' {
		linux /boot/vmlinuz-6.12.12-amd64 root=UUID=abcd ro single
	}
	menuentry 'Debian GNU/Linux, with Linux 6.12.10-cloud-amd64' --class debian $menuentry_id_option 'gnulinux-6.12.10-cloud-amd64-advanced-abcd-uuid' {
		linux /boot/vmlinuz-6.12.10-cloud-amd64 root=UUID=abcd ro quiet
	}
}
`

// No submenu (e.g. GRUB_DISABLE_SUBMENU=y or a single kernel): the versioned
// entry sits at the top level.
const sampleGrubCfgNoSubmenu = `
menuentry 'Ubuntu, with Linux 6.8.0-45-generic' --class ubuntu $menuentry_id_option 'gnulinux-6.8.0-45-generic-advanced-xyz' {
	linux /boot/vmlinuz-6.8.0-45-generic root=UUID=xyz ro
}
menuentry 'Ubuntu, with Linux 6.8.0-45-generic (recovery mode)' --class ubuntu $menuentry_id_option 'gnulinux-6.8.0-45-generic-recovery-xyz' {
	linux /boot/vmlinuz-6.8.0-45-generic root=UUID=xyz ro recovery nomodeset
}
`

func TestParseGrubEntryID(t *testing.T) {
	tests := []struct {
		name    string
		cfg     string
		version string
		want    string
		wantErr bool
	}{
		{
			name:    "generic entry inside submenu, skips recovery",
			cfg:     sampleGrubCfg,
			version: "6.12.12-amd64",
			want:    "gnulinux-advanced-abcd-uuid>gnulinux-6.12.12-amd64-advanced-abcd-uuid",
		},
		{
			name:    "older cloud kernel still resolvable if targeted",
			cfg:     sampleGrubCfg,
			version: "6.12.10-cloud-amd64",
			want:    "gnulinux-advanced-abcd-uuid>gnulinux-6.12.10-cloud-amd64-advanced-abcd-uuid",
		},
		{
			name:    "no submenu, top-level entry",
			cfg:     sampleGrubCfgNoSubmenu,
			version: "6.8.0-45-generic",
			want:    "gnulinux-6.8.0-45-generic-advanced-xyz",
		},
		{
			name:    "unknown version errors",
			cfg:     sampleGrubCfg,
			version: "9.9.9-nope",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseGrubEntryID(tt.cfg, tt.version)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got id %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestKernelPackageFallbacks(t *testing.T) {
	tests := []struct {
		pkg  string
		want []string
	}{
		{"linux-modules-extra-6.8.0-45-generic", []string{"linux-generic", "linux-image-generic"}},
		{"kernel-modules-extra-6.12.0-0.fc41.x86_64", []string{"kernel-modules-extra"}},
		{"linux-image-amd64", nil},
		{"kernel-default-extra", []string{"kernel-default"}},
	}
	for _, tt := range tests {
		got := kernelPackageFallbacks(tt.pkg)
		if len(got) != len(tt.want) {
			t.Fatalf("%s: got %v, want %v", tt.pkg, got, tt.want)
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Fatalf("%s: got %v, want %v", tt.pkg, got, tt.want)
			}
		}
	}
}
