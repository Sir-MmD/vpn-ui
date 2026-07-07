package service

import (
	"testing"
	"time"
)

func TestNormUserLimitStrategy(t *testing.T) {
	cases := map[string]string{
		"accept": "accept",
		"reject": "reject",
		"":       "reject", // unset/legacy defaults to reject
		"bogus":  "reject",
	}
	for in, want := range cases {
		if got := normUserLimitStrategy(in); got != want {
			t.Errorf("normUserLimitStrategy(%q) = %q want %q", in, got, want)
		}
	}
}

// TestAllocateBlockIPFreeAndReject covers the two I/O-free allocator paths at the
// User Limit cap. K=6 (even, non-power-of-two) confirms block-size agnosticism.
// The accept-eviction path is covered by TestOldestBlockSession (its selection)
// plus the E2E harness (its disconnect side effects).
func TestAllocateBlockIPFreeAndReject(t *testing.T) {
	subs := []string{"10.0.5"}
	const k = 6 // account 0 -> hosts .6 .. .11

	// free slot: hand out the lowest device IP, no deny.
	s := &RadiusService{sessions: map[string]*radiusSession{}}
	ip, deny := s.allocateBlockIP(0, k, subs, "l2tp", "reject")
	if deny || ip == nil || ip.String() != "10.0.5.6" {
		t.Fatalf("free slot: got ip=%v deny=%v want 10.0.5.6/false", ip, deny)
	}

	// full + reject: deny the dial.
	full := map[string]*radiusSession{}
	for d := 0; d < k; d++ {
		full["sess-"+itoa(d)] = &radiusSession{ip: "10.0.5." + itoa(6+d), protocol: "l2tp", started: time.Now()}
	}
	s = &RadiusService{sessions: full}
	if ip, deny := s.allocateBlockIP(0, k, subs, "l2tp", "reject"); ip != nil || !deny {
		t.Fatalf("full+reject: got ip=%v deny=%v want nil/true", ip, deny)
	}
}

// TestOldestBlockSession verifies the accept-strategy victim selection picks the
// longest-connected device inside the account's block and ignores other accounts.
func TestOldestBlockSession(t *testing.T) {
	base := time.Now()
	block := map[string]bool{"10.0.5.6": true, "10.0.5.7": true, "10.0.5.8": true}
	sessions := map[string]*radiusSession{
		"a": {ip: "10.0.5.7", started: base.Add(-10 * time.Minute)},
		"b": {ip: "10.0.5.6", started: base.Add(-30 * time.Minute)}, // oldest in block
		"c": {ip: "10.0.5.8", started: base.Add(-5 * time.Minute)},
		"d": {ip: "10.0.9.6", started: base.Add(-99 * time.Minute)}, // older, but other account
	}
	sid, ip := oldestBlockSession(sessions, block)
	if sid != "b" || ip != "10.0.5.6" {
		t.Fatalf("oldestBlockSession = (%q,%q) want (b,10.0.5.6)", sid, ip)
	}

	// No block member connected -> no victim.
	if sid, ip := oldestBlockSession(map[string]*radiusSession{
		"x": {ip: "10.0.9.9", started: base},
	}, block); sid != "" || ip != "" {
		t.Fatalf("no member: got (%q,%q) want empty", sid, ip)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
