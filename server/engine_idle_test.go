package server

import (
	"testing"
	"time"
)

// TestIdleClock pins the progress-clock semantics the idle settle path relies on:
// a missing stamp reads as "no idle time", and an explicit stamp is honoured.
func TestIdleClock(t *testing.T) {
	e := &Engine{}

	if got := e.idleFor("t1"); got != 0 {
		t.Fatalf("idleFor on unseen task = %v, want 0", got)
	}

	e.markProductiveIfAbsent("t1")
	if got := e.idleFor("t1"); got > 5*time.Second {
		t.Fatalf("idleFor right after seed = %v, want near 0", got)
	}

	// A stale stamp (3h ago) must report roughly 3h, i.e. past the 2h threshold.
	e.lastProd.Store("t1", time.Now().Add(-3*time.Hour).Unix())
	if got := e.idleFor("t1"); got < 2*time.Hour {
		t.Fatalf("idleFor with 3h-old stamp = %v, want >= 2h", got)
	}

	// Resume-style mark clears the backlog.
	e.markProductive("t1")
	if got := e.idleFor("t1"); got > 5*time.Second {
		t.Fatalf("idleFor after markProductive = %v, want near 0", got)
	}
}

// TestPlannerEmptyCounter pins the consecutive-empty-round counter used by the
// escalation directive.
func TestPlannerEmptyCounter(t *testing.T) {
	e := &Engine{}
	if got := e.plannerEmptyRounds("t2"); got != 0 {
		t.Fatalf("initial = %d, want 0", got)
	}
	if got := e.bumpPlannerEmpty("t2"); got != 1 {
		t.Fatalf("bump 1 = %d, want 1", got)
	}
	if got := e.bumpPlannerEmpty("t2"); got != 2 {
		t.Fatalf("bump 2 = %d, want 2", got)
	}
	if got := e.plannerEmptyRounds("t2"); got != 2 {
		t.Fatalf("read = %d, want 2", got)
	}
	e.clearPlannerEmpty("t2")
	if got := e.plannerEmptyRounds("t2"); got != 0 {
		t.Fatalf("after clear = %d, want 0", got)
	}
}

// TestIsPlannerStateChange guards which tools count as real progress.
func TestIsPlannerStateChange(t *testing.T) {
	yes := []string{"add_intent", "prove_goal", "goal_met", "conclude_no_high_impact",
		"set_goals", "set_constraints", "add_hint", "kill_work", "steer_work"}
	no := []string{"node_detail", "list_facts", "list_findings", "graph_overview",
		"get_worker_trace", "search_all_worker_traces", "list_assets", ""}
	for _, n := range yes {
		if !isPlannerStateChange(n) {
			t.Errorf("%q should count as progress", n)
		}
	}
	for _, n := range no {
		if isPlannerStateChange(n) {
			t.Errorf("%q should NOT count as progress", n)
		}
	}
}

// TestRecentLLMFailure pins the guard that keeps a dead LLM endpoint from
// triggering the idle close: failures inside the grace window suppress it.
func TestRecentLLMFailure(t *testing.T) {
	e := &Engine{}
	if e.recentLLMFailure("t3") {
		t.Fatal("unseen task should report no failure")
	}
	e.markLLMFailure("t3")
	if !e.recentLLMFailure("t3") {
		t.Fatal("failure just recorded should be recent")
	}
	// A stale stamp (older than the grace window) must not suppress closing.
	e.llmFail.Store("t3", time.Now().Add(-plannerLLMFailureGrace-time.Minute).Unix())
	if e.recentLLMFailure("t3") {
		t.Fatal("failure older than grace should not count")
	}
}
