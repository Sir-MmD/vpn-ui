package service

import "testing"

const testNow = int64(1_000_000_000_000)

func clientMap(expiry, total int64, enable bool) map[string]any {
	// Numbers arrive as float64 from JSON decoding; mirror that here.
	return map[string]any{
		"email":      "u@t",
		"expiryTime": float64(expiry),
		"totalGB":    float64(total),
		"enable":     enable,
	}
}

func int64Of(v any) int64 { return bulkNumToInt64(v) }

func TestApplyBulkClientOp(t *testing.T) {
	const day = bulkMsPerDay
	tests := []struct {
		name       string
		expiry     int64
		total      int64
		enable     bool
		req        BulkClientUpdateRequest
		wantApply  bool
		wantExpiry int64 // checked only when the op is a day op
		wantTotal  int64 // checked only when the op is a traffic op
		wantEnable bool  // checked only when the op is enable/disable
	}{
		// addDays across the three expiryTime regimes.
		{"addDays absolute", 5000, 0, true, BulkClientUpdateRequest{Op: "addDays", Days: 2}, true, 5000 + 2*day, 0, false},
		{"addDays delayed grows", -3 * day, 0, true, BulkClientUpdateRequest{Op: "addDays", Days: 2}, true, -5 * day, 0, false},
		{"addDays no-expiry anchors now", 0, 0, true, BulkClientUpdateRequest{Op: "addDays", Days: 2}, true, testNow + 2*day, 0, false},
		{"addDays skipUnlimited skips no-expiry", 0, 0, true, BulkClientUpdateRequest{Op: "addDays", Days: 2, SkipUnlimited: true}, false, 0, 0, false},

		// subDays.
		{"subDays absolute", 10 * day, 0, true, BulkClientUpdateRequest{Op: "subDays", Days: 3}, true, 7 * day, 0, false},
		{"subDays delayed clamps at 0", -1 * day, 0, true, BulkClientUpdateRequest{Op: "subDays", Days: 3}, true, 0, 0, false},
		{"subDays no-expiry is no-op", 0, 0, true, BulkClientUpdateRequest{Op: "subDays", Days: 3}, false, 0, 0, false},

		// Traffic ops (amount in bytes).
		{"addTraffic limited", 0, 1000, true, BulkClientUpdateRequest{Op: "addTraffic", AmountBytes: 500}, true, 0, 1500, false},
		{"addTraffic converts unlimited when not skipped", 0, 0, true, BulkClientUpdateRequest{Op: "addTraffic", AmountBytes: 500}, true, 0, 500, false},
		{"addTraffic skipUnlimited skips unlimited", 0, 0, true, BulkClientUpdateRequest{Op: "addTraffic", AmountBytes: 500, SkipUnlimited: true}, false, 0, 0, false},
		{"subTraffic limited", 0, 1000, true, BulkClientUpdateRequest{Op: "subTraffic", AmountBytes: 300}, true, 0, 700, false},
		{"subTraffic floors at 1 not 0", 0, 1000, true, BulkClientUpdateRequest{Op: "subTraffic", AmountBytes: 5000}, true, 0, 1, false},
		{"subTraffic unlimited is no-op", 0, 0, true, BulkClientUpdateRequest{Op: "subTraffic", AmountBytes: 5000}, false, 0, 0, false},

		// enable / disable.
		{"enable disabled", 0, 0, false, BulkClientUpdateRequest{Op: "enable"}, true, 0, 0, true},
		{"enable already-enabled no-op", 0, 0, true, BulkClientUpdateRequest{Op: "enable"}, false, 0, 0, true},
		{"disable enabled", 0, 0, true, BulkClientUpdateRequest{Op: "disable"}, true, 0, 0, false},
		{"disable already-disabled no-op", 0, 0, false, BulkClientUpdateRequest{Op: "disable"}, false, 0, 0, false},

		// Skip toggles independent of op.
		{"skipFirstUse skips delayed", -2 * day, 100, true, BulkClientUpdateRequest{Op: "addTraffic", AmountBytes: 50, SkipFirstUse: true}, false, 0, 0, false},
		{"skipDisabled skips disabled", 5000, 100, false, BulkClientUpdateRequest{Op: "addTraffic", AmountBytes: 50, SkipDisabled: true}, false, 0, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := clientMap(tt.expiry, tt.total, tt.enable)
			got := applyBulkClientOp(cm, tt.req, testNow)
			if got != tt.wantApply {
				t.Fatalf("apply = %v, want %v", got, tt.wantApply)
			}
			if !got {
				return // skipped: nothing should have changed
			}
			switch tt.req.Op {
			case "addDays", "subDays":
				if e := int64Of(cm["expiryTime"]); e != tt.wantExpiry {
					t.Errorf("expiryTime = %d, want %d", e, tt.wantExpiry)
				}
			case "addTraffic", "subTraffic":
				if v := int64Of(cm["totalGB"]); v != tt.wantTotal {
					t.Errorf("totalGB = %d, want %d", v, tt.wantTotal)
				}
			case "enable", "disable":
				if b, _ := cm["enable"].(bool); b != tt.wantEnable {
					t.Errorf("enable = %v, want %v", b, tt.wantEnable)
				}
			}
		})
	}
}

func TestBulkUnknownOpRejected(t *testing.T) {
	s := &InboundService{}
	_, _, err := s.BulkUpdateClients(BulkClientUpdateRequest{Op: "nuke"})
	if err == nil {
		t.Fatal("expected error for unknown op")
	}
}
