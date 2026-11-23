package agent

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

// TestMinReportSeverityGate pins the floor resolver: unset/unknown disables the
// gate, and the canonical names resolve in rank order.
func TestMinReportSeverityGate(t *testing.T) {
	orig := MinReportSeverity
	defer func() { MinReportSeverity = orig }()

	cases := []struct {
		set  string
		want string
	}{
		{"", ""},           // unset → no gate
		{"low", "low"},     // explicit low = gate at low (accepts everything valid)
		{"medium", "medium"},
		{"high", "high"},
		{"critical", "critical"},
		{"HIGH", "high"},   // normalised
		{"  high  ", "high"},
		{"bogus", ""},      // unknown → gate disabled rather than blocking everything
	}
	for _, c := range cases {
		set := c.set
		MinReportSeverity = func() string { return set }
		if got := minReportSeverity(); got != c.want {
			t.Errorf("minReportSeverity() with %q = %q, want %q", c.set, got, c.want)
		}
	}

	// nil hook → no gate.
	MinReportSeverity = nil
	if got := minReportSeverity(); got != "" {
		t.Errorf("minReportSeverity() with nil hook = %q, want empty", got)
	}
}

// TestSeverityRankOrder guards the ordering the gate relies on.
func TestSeverityRankOrder(t *testing.T) {
	order := []string{
		db.SeverityLow, db.SeverityMedium, db.SeverityHigh, db.SeverityCritical,
	}
	for i := 1; i < len(order); i++ {
		if severityRank(order[i]) <= severityRank(order[i-1]) {
			t.Fatalf("severityRank not increasing: %s(%d) vs %s(%d)",
				order[i], severityRank(order[i]), order[i-1], severityRank(order[i-1]))
		}
	}
}
