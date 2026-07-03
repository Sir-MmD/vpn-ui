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
	got, err := normalizePppRanges("l2tp", nil, 5, map[string]bool{"10.0.2": true})
	if err != nil || len(got) != 1 || rangeSubnet(got[0]) != "10.0.3" {
		t.Fatalf("auto-assign got %v err %v", got, err)
	}

	// Overlap with another inbound -> rejected.
	if _, err := normalizePppRanges("l2tp", []string{"10.0.2.10-10.0.2.50"}, 1, map[string]bool{"10.0.2": true}); err == nil {
		t.Errorf("expected overlap rejection")
	}

	// Auto-expand: 100 clients needs a second /24 (default window is 241).
	got, err = normalizePppRanges("l2tp", []string{"10.0.5.10-10.0.5.50"}, 100, map[string]bool{})
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
	got, err := normalizeOvpnRanges(7, 50, map[string]bool{})
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
	got, err := normalizeOvpnRanges(8, 300, map[string]bool{})
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
