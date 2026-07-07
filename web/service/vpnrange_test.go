package service

import (
	"net"
	"testing"
)

func TestParseRange(t *testing.T) {
	cases := []struct {
		in        string
		wantStart string
		wantEnd   string
		wantOK    bool
	}{
		{"10.0.5.10-10.0.5.250", "10.0.5.10", "10.0.5.250", true},
		{"10.0.5.10-50", "10.0.5.10", "10.0.5.50", true}, // shorthand
		{" 10.1.2.10 - 10.1.2.20 ", "10.1.2.10", "10.1.2.20", true},
		{"10.0.5.10-10.0.6.20", "", "", false}, // spans two /24s
		{"10.0.5.50-10.0.5.10", "", "", false}, // reversed
		{"garbage", "", "", false},
		{"10.0.5.10", "", "", false}, // no dash
	}
	for _, c := range cases {
		start, end, ok := parseRange(c.in)
		if ok != c.wantOK {
			t.Errorf("parseRange(%q) ok=%v want %v", c.in, ok, c.wantOK)
			continue
		}
		if ok && (start.String() != c.wantStart || end.String() != c.wantEnd) {
			t.Errorf("parseRange(%q) = %v-%v want %v-%v", c.in, start, end, c.wantStart, c.wantEnd)
		}
	}
}

func TestRangeCapacity(t *testing.T) {
	got := rangeCapacity([]string{"10.0.5.10-10.0.5.50", "10.0.6.2-10.0.6.254"})
	want := 41 + 253
	if got != want {
		t.Errorf("rangeCapacity = %d want %d", got, want)
	}
}

func TestComputeVpnClientIPMultiRange(t *testing.T) {
	ranges := []string{"10.0.5.10-10.0.5.12", "10.0.6.20-10.0.6.21"} // caps 3 then 2
	want := []string{"10.0.5.10", "10.0.5.11", "10.0.5.12", "10.0.6.20", "10.0.6.21"}
	for i, w := range want {
		got := computeVpnClientIP(ranges, 7, i, "l2tp")
		if got == nil || got.String() != w {
			t.Errorf("computeVpnClientIP idx %d = %v want %s", i, got, w)
		}
	}
	if ip := computeVpnClientIP(ranges, 7, 5, "l2tp"); ip != nil {
		t.Errorf("index past capacity should be nil, got %v", ip)
	}
}

func TestNextFreeSubnet(t *testing.T) {
	used := map[string]bool{"10.0.2": true, "10.0.3": true}
	if got := nextFreeSubnet("l2tp", used); got != "10.0.4" {
		t.Errorf("nextFreeSubnet l2tp = %q want 10.0.4", got)
	}
	if got := nextFreeSubnet("pptp", used); got != "10.1.2" {
		t.Errorf("nextFreeSubnet pptp = %q want 10.1.2", got)
	}
}

func TestNormalizePppRanges(t *testing.T) {
	// Empty -> auto-assign first free /24.
	got, err := normalizePppRanges("l2tp", nil, 5, 1, map[string]bool{"10.0.2": true})
	if err != nil || len(got) != 1 || rangeSubnet(got[0]) != "10.0.3" {
		t.Fatalf("auto-assign got %v err %v", got, err)
	}

	// Overlap with another inbound -> rejected.
	if _, err := normalizePppRanges("l2tp", []string{"10.0.2.10-10.0.2.50"}, 1, 1, map[string]bool{"10.0.2": true}); err == nil {
		t.Errorf("expected overlap rejection")
	}

	// Auto-expand: 100 clients needs a second /24 (default window is 241).
	got, err = normalizePppRanges("l2tp", []string{"10.0.5.10-10.0.5.50"}, 100, 1, map[string]bool{})
	if err != nil {
		t.Fatalf("auto-expand err %v", err)
	}
	if rangeCapacity(got) < 100 {
		t.Errorf("auto-expand capacity %d < 100 (ranges %v)", rangeCapacity(got), got)
	}
	if len(got) < 2 {
		t.Errorf("expected an appended range, got %v", got)
	}
}

func TestNormalizeOvpnRangesLegacyIdentity(t *testing.T) {
	// <=253 clients on inbound id 7 -> single 10.2.7 /24, byte-identical legacy.
	got, err := normalizeOvpnRanges(7, 50, 1, map[string]bool{})
	if err != nil {
		t.Fatalf("err %v", err)
	}
	if len(got) != 1 || rangeSubnet(got[0]) != "10.2.7" {
		t.Errorf("legacy ovpn block = %v want single 10.2.7", got)
	}
	netAddr, prefix := ovpnBlock(got, "udp", 7)
	if netAddr.String() != "10.2.7.0" || prefix != 24 {
		t.Errorf("ovpnBlock = %s/%d want 10.2.7.0/24", netAddr, prefix)
	}
	tcpNet, _ := ovpnBlock(got, "tcp", 7)
	if tcpNet.String() != "10.3.7.0" {
		t.Errorf("tcp mirror = %s want 10.3.7.0", tcpNet)
	}
}

func TestNormalizeOvpnRangesGrows(t *testing.T) {
	// 300 clients needs 2 /24s -> an aligned /23 block.
	got, err := normalizeOvpnRanges(8, 300, 1, map[string]bool{})
	if err != nil {
		t.Fatalf("err %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 /24s, got %v", got)
	}
	netAddr, prefix := ovpnBlock(got, "udp", 8)
	if prefix != 23 {
		t.Errorf("prefix = %d want 23 (%v)", prefix, got)
	}
	// /23 network address must be aligned (even third octet).
	if netAddr[2]%2 != 0 {
		t.Errorf("block not /23-aligned: %s", netAddr)
	}
	// Client indices span both /24s and are distinct.
	seen := map[string]bool{}
	for i := 0; i < 300; i++ {
		ip := ovpnBlockClientIP(netAddr, prefix, i)
		if ip == "" || seen[ip] {
			t.Fatalf("bad/dup ovpn client ip at %d: %q", i, ip)
		}
		seen[ip] = true
	}
}

func TestOvpnBlockClientIPBounds(t *testing.T) {
	netAddr := net.IPv4(10, 2, 7, 0).To4()
	// /24: hosts .2..254 => 253 clients (indices 0..252); index 253 overflows.
	if ip := ovpnBlockClientIP(netAddr, 24, 252); ip != "10.2.7.254" {
		t.Errorf("last client = %q want 10.2.7.254", ip)
	}
	if ip := ovpnBlockClientIP(netAddr, 24, 253); ip != "" {
		t.Errorf("overflow client = %q want empty", ip)
	}
}

// ---- User Limit (per-account CIDR blocks) ----------------------------------

func TestNormUserLimit(t *testing.T) {
	// Clamp to [1,64]; ANY integer allowed (not just powers of two).
	cases := map[int]int{0: 1, 1: 1, 2: 2, 3: 3, 6: 6, 7: 7, 10: 10, 64: 64, 65: 64, 1000: 64}
	for in, want := range cases {
		if got := normUserLimit(in); got != want {
			t.Errorf("normUserLimit(%d) = %d want %d", in, got, want)
		}
	}
}

func TestAccountsPerSubnet(t *testing.T) {
	// Powers of two stay byte-identical to the legacy 256/K-2 sizing; non-pow2 K
	// use floor(255/K)-1 (account s occupies hosts [(s+1)*K, (s+2)*K-1] <= 254).
	cases := map[int]int{
		1: 253, 2: 126, 4: 62, 8: 30, 16: 14, 32: 6, 64: 2, // powers of two
		3: 84, 6: 41, 10: 24, 50: 4, // even / odd non-powers of two
	}
	for k, want := range cases {
		if got := accountsPerSubnet(k); got != want {
			t.Errorf("accountsPerSubnet(%d) = %d want %d", k, got, want)
		}
	}
}

func TestVpnAccountDeviceIPs(t *testing.T) {
	subs := []string{"10.0.5", "10.0.6"}
	eq := func(a, b []string) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}
	// K=6 (non power of two): account 0 -> hosts .6..11, account 1 -> .12..17.
	if got := vpnAccountDeviceIPs(subs, 0, 6); !eq(got, []string{
		"10.0.5.6", "10.0.5.7", "10.0.5.8", "10.0.5.9", "10.0.5.10", "10.0.5.11"}) {
		t.Errorf("K=6 acct0 = %v", got)
	}
	if got := vpnAccountDeviceIPs(subs, 1, 6); !eq(got, []string{
		"10.0.5.12", "10.0.5.13", "10.0.5.14", "10.0.5.15", "10.0.5.16", "10.0.5.17"}) {
		t.Errorf("K=6 acct1 = %v", got)
	}
	// K=64 still works (legacy pow2 block): account 0 -> .64..127.
	if got := vpnAccountDeviceIPs(subs, 0, 64); len(got) != 64 || got[0] != "10.0.5.64" || got[63] != "10.0.5.127" {
		t.Errorf("K=64 acct0 = %v", got)
	}
	// Spill into the 2nd /24 once the first fills (accountsPerSubnet(6) accounts).
	if got := vpnAccountDeviceIPs(subs, accountsPerSubnet(6), 6); len(got) == 0 || got[0] != "10.0.6.6" {
		t.Errorf("spill acct = %v", got)
	}
	// Past total capacity -> nil.
	if got := vpnAccountDeviceIPs(subs, 2*accountsPerSubnet(6), 6); got != nil {
		t.Errorf("overflow = %v want nil", got)
	}
}

func TestVpnAccountDeviceIP(t *testing.T) {
	subs := []string{"10.0.5"}
	// Account 0, K=4 -> block .4/30 -> devices .4,.5,.6,.7; device 4 out of range.
	want := []string{"10.0.5.4", "10.0.5.5", "10.0.5.6", "10.0.5.7"}
	for d, w := range want {
		if got := vpnAccountDeviceIP(subs, 0, 4, d); got != w {
			t.Errorf("device %d = %q want %q", d, got, w)
		}
	}
	if got := vpnAccountDeviceIP(subs, 0, 4, 4); got != "" {
		t.Errorf("device 4 (>=K) = %q want empty", got)
	}
	// Every device IP across all accounts in a /24 must be distinct and never hit
	// .0/.1 (network/gateway) or .255 (broadcast) — for pow2 AND non-pow2 K.
	for _, k := range []int{8, 6, 10} {
		seen := map[string]bool{}
		for i := 0; i < accountsPerSubnet(k); i++ {
			for d := 0; d < k; d++ {
				ip := vpnAccountDeviceIP(subs, i, k, d)
				if ip == "" || seen[ip] {
					t.Fatalf("bad/dup device ip K=%d acct=%d dev=%d: %q", k, i, d, ip)
				}
				seen[ip] = true
				last := ip[len("10.0.5."):]
				if last == "0" || last == "1" || last == "255" {
					t.Errorf("K=%d device ip hit reserved address: %q", k, ip)
				}
			}
		}
	}
}

func TestNormalizePppRangesUserLimit(t *testing.T) {
	// K=64 -> 2 accounts per /24. 5 accounts needs 3 /24s.
	got, err := normalizePppRanges("l2tp", nil, 5, 64, map[string]bool{})
	if err != nil {
		t.Fatalf("err %v", err)
	}
	if vpnAccountsCapacity(subnetsOf(got), 64) < 5 {
		t.Errorf("capacity %d < 5 accounts (ranges %v)", vpnAccountsCapacity(subnetsOf(got), 64), got)
	}
	if len(got) != 3 {
		t.Errorf("expected 3 /24s for 5 K=64 accounts, got %v", got)
	}
}

func TestNormalizeOvpnRangesUserLimit(t *testing.T) {
	// K=64 -> 2 accounts/24. 5 accounts -> need 3 -> round up to 4 /24s (/22).
	got, err := normalizeOvpnRanges(8, 5, 64, map[string]bool{})
	if err != nil {
		t.Fatalf("err %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("expected 4 /24s (pow2 >= 3), got %v", got)
	}
	_, prefix := ovpnBlock(got, "udp", 8)
	if prefix != 22 {
		t.Errorf("prefix = %d want 22", prefix)
	}
}
