// Copyright and license: see repository LICENSE (MIT).
package proxy

import "testing"

// TestJobManager_CurrentTargetDiffForRoute_NoTemplate is the
// DISPATCH_BRIEF.md 2026-09-13 ("cap starting/min difficulty to the
// pool's own target_diff") required test 4's genuinely-nil-template
// half: currentTargetDiffForRoute must report ok==false, with NO
// panic and no invented value, when the route's own TemplateSource
// has no current template at all yet -- session.go's handleLogin
// treats that identically to "no pool diff known yet, don't invent
// one" and skips the login-time cap entirely (see that function's
// doc comment). Exercised directly against JobManager rather than
// through a full login (a genuinely nil CurrentTemplate() also fails
// handleLogin's own, unrelated, pre-existing "no job template
// available yet" path via currentJob/NextJob -- see
// forced_min_difficulty_test.go's
// TestSessionLogin_NoPoolTemplateYet_FallsBackToUncappedFloors for the
// TargetDiff==0-on-a-live-template half of required test 4, which
// exercises the cap through a real login all the way to a successful
// response).
func TestJobManager_CurrentTargetDiffForRoute_NoTemplate(t *testing.T) {
	source := newFakeTemplateSource(nil)
	jm := NewJobManager(source, nil)

	diff, ok := jm.currentTargetDiffForRoute(RoutePrimary)
	if ok {
		t.Fatalf("expected ok=false with no current template, got ok=true diff=%d", diff)
	}
	if diff != 0 {
		t.Fatalf("expected diff=0 with no current template, got %d", diff)
	}
}

// TestJobManager_CurrentTargetDiffForRoute_ReportsTargetDiff is the
// straightforward positive case: currentTargetDiffForRoute surfaces
// exactly WorkerTemplate.TargetDiff, unmodified, for the primary
// route.
func TestJobManager_CurrentTargetDiffForRoute_ReportsTargetDiff(t *testing.T) {
	tmpl := poolTemplateWithTargetDiff(50_000)
	source := newFakeTemplateSource(tmpl)
	jm := NewJobManager(source, nil)

	diff, ok := jm.currentTargetDiffForRoute(RoutePrimary)
	if !ok {
		t.Fatalf("expected ok=true with a live current template")
	}
	if diff != 50_000 {
		t.Fatalf("expected diff=50000, got %d", diff)
	}
}
