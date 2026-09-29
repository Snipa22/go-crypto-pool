// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib/relay"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// sharedTemplateStampedeSessionCount is the number of genuinely DIFFERENT
// per-session job-cache keys the cold-start-stampede regression test below
// drives concurrently. The real live incident this whole file exists
// for involved ~13,500 simultaneously-reconnecting miners producing
// 41,783 "new block template fetched" log lines for the SAME block
// height inside a 90-second window (see this fix's brief), so a
// four-digit session count is the realistic shape to assert against -- not
// a token 2 or 3.
const sharedTemplateStampedeSessionCount = 1000

// TestJobForSessionSharedTemplateCollapsesColdStartStampedeToOneDaemonCall
// is THE regression test for this fix, and reproduces the real
// production incident directly: a genuine cold start (empty job cache,
// no shared template yet) with sharedTemplateStampedeSessionCount
// simultaneously-arriving sessions, every one of them carrying its own
// genuinely DIFFERENT, freshly-minted job-cache key
// (leaflib.NewJobCacheKey is
// per-connection -- see this fix's brief), must produce EXACTLY ONE
// real NodeClient.GetBlockTemplate call, not one per session.
//
// Before this fix, solo.JobManager.jobForSession called
// jm.cfg.Node.GetBlockTemplate on ANY per-session cache miss. jm.genLocks
// correctly collapsed concurrent first-requests for the SAME session
// into one fetch, but every DIFFERENT session still got its OWN independent
// daemon round trip -- so N reconnecting sessions produced N real RPC
// calls for the exact same underlying chain tip. On the live
// sxmr-phx-dump host that overloaded the upstream
// minotari_merge_mining_proxy into returning
// `rpc error -32603: Internal error`, and (because each fetch
// invalidated the job the previous session was already working)
// rejected 21-40% of submitted shares as stale/expired while genuine
// cryptographic-validation failures stayed negligible (~0.15%).
//
// This test asserts all three properties the fix must hold
// simultaneously:
//
//  1. EXACTLY ONE real GetBlockTemplate call across all N sessions.
//  2. Every session still gets its OWN distinct Job.ID (per-session
//     Job objects are preserved -- this fix shares the underlying
//     TEMPLATE, never one literal *Job handed to every session; see
//     the brief's "What NOT to change" section).
//  3. Every session's Job carries EXACTLY the difficulty THAT session
//     asked for, never some other concurrently-arriving session's.
func TestJobForSessionSharedTemplateCollapsesColdStartStampedeToOneDaemonCall(t *testing.T) {
	node := &fakeNodeClient{height: 3_500_100, targetDifficulty: 900_000, mergeMiningHash: []byte("shared-tip-merge-mining-hash-32b")}
	jm := NewJobManager(JobManagerConfig{
		Node:          node,
		Algo:          poolpb.Algo_ALGO_RXM,
		PayoutAddress: "shared-template-payout-address",
	})

	type result struct {
		job *Job
		err error
	}
	results := make([]result, sharedTemplateStampedeSessionCount)
	sessionKeys := make([]string, sharedTemplateStampedeSessionCount)
	difficulties := make([]uint64, sharedTemplateStampedeSessionCount)
	for i := range sessionKeys {
		// Genuinely different job-cache key per simulated session, and a
		// genuinely different difficulty per simulated session, so a
		// cross-session difficulty leak cannot hide behind two
		// sessions coincidentally sharing a value.
		sessionKeys[i] = fmt.Sprintf("%04x", i)
		difficulties[i] = 10_000 + uint64(i)
	}

	// All N sessions released at the exact same instant, mirroring a
	// real mass-reconnect far more closely than a staggered loop.
	var start sync.WaitGroup
	start.Add(1)
	var done sync.WaitGroup
	for i := 0; i < sharedTemplateStampedeSessionCount; i++ {
		i := i
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			job, err := jm.JobForSessionAtDifficulty(context.Background(), sessionKeys[i], difficulties[i])
			results[i] = result{job: job, err: err}
		}()
	}
	start.Done()
	done.Wait()

	// (1) The whole point: ONE real daemon call, not N.
	if got := node.templateCalls.Load(); got != 1 {
		t.Errorf("GetBlockTemplate was called %d times for %d concurrent first-time requests across %d DIFFERENT sessions; want EXACTLY 1 -- this is the live production incident (41,783 fetches for one block height) this fix exists to prevent",
			got, sharedTemplateStampedeSessionCount, sharedTemplateStampedeSessionCount)
	}

	seenIDs := make(map[string]int, sharedTemplateStampedeSessionCount)
	for i, res := range results {
		if res.err != nil {
			t.Fatalf("JobForSessionAtDifficulty(session=%s): %v", sessionKeys[i], res.err)
		}
		if res.job == nil {
			t.Fatalf("JobForSessionAtDifficulty(session=%s) returned a nil Job with no error", sessionKeys[i])
		}
		// (2) Own distinct Job.ID per session.
		if prev, dup := seenIDs[res.job.ID]; dup {
			t.Fatalf("session %s and session %s were handed the SAME Job.ID %q -- every session must keep its OWN job id for submit-time ownership/replay protection",
				sessionKeys[prev], sessionKeys[i], res.job.ID)
		}
		seenIDs[res.job.ID] = i
		// (3) Own correctly-stamped difficulty per session.
		if res.job.StaticDifficulty != difficulties[i] {
			t.Fatalf("session %s got StaticDifficulty %d, want exactly the %d IT requested (a cross-session difficulty leak)",
				sessionKeys[i], res.job.StaticDifficulty, difficulties[i])
		}
		// Every session must still be mining the one real shared tip.
		if res.job.Height != 3_500_100 {
			t.Fatalf("session %s got Height %d, want the shared template's real height 3500100", sessionKeys[i], res.job.Height)
		}
		if res.job.NetworkTargetDifficulty != 900_000 {
			t.Fatalf("session %s got NetworkTargetDifficulty %d, want the shared template's real 900000", sessionKeys[i], res.job.NetworkTargetDifficulty)
		}
	}
	if len(seenIDs) != sharedTemplateStampedeSessionCount {
		t.Errorf("got %d distinct Job.IDs across %d sessions, want %d", len(seenIDs), sharedTemplateStampedeSessionCount, sharedTemplateStampedeSessionCount)
	}
}

// TestJobForSessionSharedTemplateSequentialSessionsStillShareOneTemplate is the
// non-concurrent counterpart to the stampede test above: the fix must
// not depend on requests arriving simultaneously to collapse. A slow
// trickle of genuinely different sessions (the ordinary steady-state
// connect pattern, as opposed to a mass reconnect) must ALSO share the
// one established template rather than each fetching its own.
func TestJobForSessionSharedTemplateSequentialSessionsStillShareOneTemplate(t *testing.T) {
	node := &fakeNodeClient{height: 900, targetDifficulty: 5000}
	jm := NewJobManager(JobManagerConfig{
		Node: node, Algo: poolpb.Algo_ALGO_RXM, PayoutAddress: "solo-test-address",
	})

	var firstHeader []byte
	for i := 0; i < 25; i++ {
		sessionKey := fmt.Sprintf("s%03d", i)
		job, err := jm.JobForSessionAtDifficulty(context.Background(), sessionKey, 4000+uint64(i))
		if err != nil {
			t.Fatalf("JobForSessionAtDifficulty(session=%s): %v", sessionKey, err)
		}
		if job.StaticDifficulty != 4000+uint64(i) {
			t.Fatalf("session %s: StaticDifficulty = %d, want %d", sessionKey, job.StaticDifficulty, 4000+uint64(i))
		}
		if i == 0 {
			firstHeader = job.Header
			continue
		}
		// Every session must be mining the SAME underlying template
		// material (that is the whole point), while still holding its
		// own Job identity/difficulty.
		if string(job.Header) != string(firstHeader) {
			t.Fatalf("session %s got different Header material than the first session -- all sessions should derive from the one shared template", sessionKey)
		}
	}

	if got := node.templateCalls.Load(); got != 1 {
		t.Errorf("GetBlockTemplate was called %d times across 25 sequential distinct sessions; want EXACTLY 1", got)
	}
}

// TestJobForSessionSharedTemplateSameSessionRepeatRequestReturnsSameJob proves
// this fix PRESERVES JobForSession's long-standing per-session contract (see
// that method's doc comment, and
// TestJobForSessionIsStableForSameSessionUntilInvalidated for the Tari-path
// equivalent): repeat requests for the SAME session against the same cache
// generation return the SAME cached *Job, i.e. a consistent job_id
// across getjob calls -- the shared-template derivation must not
// re-mint a fresh job id on every call.
func TestJobForSessionSharedTemplateSameSessionRepeatRequestReturnsSameJob(t *testing.T) {
	node := &fakeNodeClient{height: 77}
	jm := NewJobManager(JobManagerConfig{
		Node: node, Algo: poolpb.Algo_ALGO_RXM, PayoutAddress: "solo-test-address",
	})

	first, err := jm.JobForSessionAtDifficulty(context.Background(), "abcd", 1234)
	if err != nil {
		t.Fatalf("JobForSessionAtDifficulty (first): %v", err)
	}
	second, err := jm.JobForSessionAtDifficulty(context.Background(), "abcd", 9999)
	if err != nil {
		t.Fatalf("JobForSessionAtDifficulty (repeat): %v", err)
	}
	if first != second {
		t.Error("expected repeat requests for the same sessionKey to return the SAME cached *Job")
	}
	// The already-cached job's stamped difficulty must NOT be
	// retroactively changed by a later differing request -- that is
	// RestampDifficulty's job, not JobForSessionAtDifficulty's.
	if second.StaticDifficulty != 1234 {
		t.Errorf("StaticDifficulty = %d, want the originally-stamped 1234 (JobForSessionAtDifficulty must not retroactively restamp a cached job)", second.StaticDifficulty)
	}
	if got := node.templateCalls.Load(); got != 1 {
		t.Errorf("GetBlockTemplate was called %d times for two repeat same-session requests; want 1", got)
	}
}

// TestJobForSessionSharedTemplateInvalidationForcesExactlyOneRefetch proves
// the ORDINARY post-invalidation case (as opposed to the first-ever
// cold start) also collapses to one daemon call. This is the exact
// shape of the second half of the live incident: pre-fix, every
// genuine tip change wiped the whole per-session cache and then EVERY
// connected session independently re-fetched, so the stampede
// recurred on every single block, not just at startup.
func TestJobForSessionSharedTemplateInvalidationForcesExactlyOneRefetch(t *testing.T) {
	node := &fakeNodeClient{height: 1000}
	jm := NewJobManager(JobManagerConfig{
		Node: node, Algo: poolpb.Algo_ALGO_RXM, PayoutAddress: "solo-test-address",
	})

	const sessions = 200
	sessionKeys := make([]string, sessions)
	for i := range sessionKeys {
		sessionKeys[i] = fmt.Sprintf("i%03d", i)
		if _, err := jm.JobForSessionAtDifficulty(context.Background(), sessionKeys[i], 100); err != nil {
			t.Fatalf("JobForSessionAtDifficulty (pre-invalidation, session=%s): %v", sessionKeys[i], err)
		}
	}
	if got := node.templateCalls.Load(); got != 1 {
		t.Fatalf("expected 1 template call to establish the shared template, got %d", got)
	}

	// A genuine invalidation (tip moved) drops the shared template.
	node.setHeight(1001)
	jm.InvalidateAll(TemplateSourceLocal)

	// Now every one of those sessions gets repushed at once -- exactly
	// what direct.Server.invalidateAndRepushJobs does.
	var start sync.WaitGroup
	start.Add(1)
	var done sync.WaitGroup
	jobs := make([]*Job, sessions)
	for i := 0; i < sessions; i++ {
		i := i
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			job, err := jm.JobForSessionAtDifficulty(context.Background(), sessionKeys[i], 100)
			if err == nil {
				jobs[i] = job
			}
		}()
	}
	start.Done()
	done.Wait()

	if got := node.templateCalls.Load(); got != 2 {
		t.Errorf("GetBlockTemplate was called %d times total; want EXACTLY 2 (one to establish the shared template, one to re-establish it after invalidation) -- NOT one per repushed session", got)
	}
	for i, job := range jobs {
		if job == nil {
			t.Fatalf("session %s got no job after invalidation", sessionKeys[i])
		}
		if job.Height != 1001 {
			t.Fatalf("session %s got Height %d after invalidation, want the new 1001", sessionKeys[i], job.Height)
		}
	}
}

// TestSharedTemplateTipChangeTriggersExactlyOneAdditionalDaemonCall
// drives the REAL tipPollLoop (via Start, not by calling InvalidateAll
// by hand) and proves the brief's explicit tip-change requirement: a
// genuine tip-height change triggers exactly ONE additional real
// GetBlockTemplate call -- the local refresh -- and NOT one per
// already-connected session, and every already-cached session's next
// request afterwards returns a Job reflecting the NEW height, derived
// from the shared template, without any further daemon call of its
// own.
func TestSharedTemplateTipChangeTriggersExactlyOneAdditionalDaemonCall(t *testing.T) {
	node := &fakeNodeClient{height: 5000, targetDifficulty: 7777}
	jm := NewJobManager(JobManagerConfig{
		Node: node, Algo: poolpb.Algo_ALGO_RXM, PayoutAddress: "solo-test-address",
		RefreshInterval: 24 * time.Hour, // disabled: only tip movement should matter here
		TipPollInterval: 10 * time.Millisecond,
	})

	invalidated := make(chan string, 16)
	unsub := jm.Subscribe(func(source string) { invalidated <- source })
	defer unsub()

	// A handful of already-connected sessions, all sharing one
	// template (1 real daemon call).
	sessionKeys := []string{"c001", "c002", "c003", "c004", "c005"}
	for _, sessionKey := range sessionKeys {
		if _, err := jm.JobForSessionAtDifficulty(context.Background(), sessionKey, 250); err != nil {
			t.Fatalf("JobForSessionAtDifficulty (pre-tip-change, session=%s): %v", sessionKey, err)
		}
	}
	if got := node.templateCalls.Load(); got != 1 {
		t.Fatalf("expected 1 template call before the tip change, got %d", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	jm.Start(ctx)

	// Let tipPollLoop seed its baseline at the current height first --
	// that first observation must NOT be misread as tip movement.
	deadline := time.Now().Add(5 * time.Second)
	for jm.LatestHeight() != 5000 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if jm.LatestHeight() != 5000 {
		t.Fatalf("tipPollLoop never seeded its baseline height (LatestHeight = %d)", jm.LatestHeight())
	}
	select {
	case src := <-invalidated:
		t.Fatalf("baseline tip observation must not invalidate anything, got a %q invalidation", src)
	case <-time.After(50 * time.Millisecond):
	}

	// Genuine tip movement.
	node.setHeight(5001)
	select {
	case src := <-invalidated:
		if src != TemplateSourceLocal {
			t.Errorf("invalidation source = %q, want %q", src, TemplateSourceLocal)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("tipPollLoop never invalidated after a genuine tip-height increase")
	}

	// Stop the poller so no further ticks can add template calls and
	// make the assertion below racy.
	cancel()
	time.Sleep(50 * time.Millisecond)
	callsAfterTipChange := node.templateCalls.Load()
	if callsAfterTipChange != 2 {
		t.Fatalf("GetBlockTemplate was called %d times after ONE genuine tip change; want EXACTLY 2 (the original + one local refresh), NOT one per connected session", callsAfterTipChange)
	}

	// Every already-connected session's next request must now see the
	// NEW height, derived from the shared template, with no further
	// daemon call.
	for _, sessionKey := range sessionKeys {
		job, err := jm.JobForSessionAtDifficulty(context.Background(), sessionKey, 250)
		if err != nil {
			t.Fatalf("JobForSessionAtDifficulty (post-tip-change, session=%s): %v", sessionKey, err)
		}
		if job.Height != 5001 {
			t.Errorf("session %s: Height = %d after the tip change, want the new 5001", sessionKey, job.Height)
		}
	}
	if got := node.templateCalls.Load(); got != callsAfterTipChange {
		t.Errorf("re-serving %d already-connected sessions after the tip change cost %d extra GetBlockTemplate calls; want 0", len(sessionKeys), got-callsAfterTipChange)
	}
}

// TestSharedTemplateRelayAdoptionNeedsNoLocalFetchForNewOrKnownSessions
// drives the REAL relay-adoption mechanism end-to-end over a REAL
// embedded NATS server (the same harness job_relay_test.go's own
// adoption tests use -- startEmbeddedNATSServerForJobTest, a genuine
// relay.PublishTemplate from a DIFFERENT Relay instance, and
// JobManager's own startTemplateRelaySubscription ->
// isBetterCandidate -> NodeClient.JobFromTemplateBytes ->
// adoptRelayedJob chain), and proves the brief's relay requirement:
// the relay-delivered template's bytes populate the shared current
// template with ZERO local GetBlockTemplate calls, and subsequent
// per-session job derivation from that relay-adopted template also
// makes zero additional daemon calls.
//
// The brand-new-session assertion is the specific gap this closes. Pre-fix,
// adoptRelayedJob only reseeded sessions ALREADY present in perSession, so a
// session connecting AFTER an adoption was an ordinary cache miss and
// fired its own local GetBlockTemplate call against the very node the
// relay adoption had just established was LAGGING.
func TestSharedTemplateRelayAdoptionNeedsNoLocalFetchForNewOrKnownSessions(t *testing.T) {
	url, shutdown := startEmbeddedNATSServerForJobTest(t)
	defer shutdown()

	jmRelay := relay.NewRelay(relay.Config{URL: url})
	defer jmRelay.Close()
	externalRelay := relay.NewRelay(relay.Config{URL: url})
	defer externalRelay.Close()
	if !jmRelay.Enabled() || !externalRelay.Enabled() {
		t.Fatalf("expected both relays to be Enabled() after connecting to a real NATS server at %s", url)
	}

	node := &fakeNodeClient{height: 50}
	jm := NewJobManager(JobManagerConfig{
		Node: node, PayoutAddress: "solo-test-address",
		Algo: poolpb.Algo_ALGO_RXM, Network: "testnet",
		RefreshInterval: 24 * time.Hour,
		TipPollInterval: 24 * time.Hour, // disabled: only the relay subscription should matter here
		Relay:           jmRelay,
	})

	// One already-known session, established from the local node
	// (1 real daemon call).
	knownJob, err := jm.JobForSessionAtDifficulty(context.Background(), "aaaa", 321)
	if err != nil {
		t.Fatalf("JobForSessionAtDifficulty (seed): %v", err)
	}
	if got := node.templateCalls.Load(); got != 1 {
		t.Fatalf("expected exactly 1 template call after seeding, got %d", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	jm.Start(ctx)
	time.Sleep(150 * time.Millisecond) // let the real NATS subscription land

	// A genuinely superior (strictly higher height) template,
	// published with REAL reconstructible content by a DIFFERENT
	// Relay instance.
	result := syntheticTariResultForAdoptionTest(51, 64)
	data := marshalSyntheticTariResultForAdoptionTest(t, result)
	if err := externalRelay.PublishTemplate(context.Background(), relay.TemplateMessage{
		Algo: "rx/0", Network: "testnet", Height: 51,
		TemplateData: data, Size: len(data), Hash: "shared-template-relay-adoption-hash",
	}); err != nil {
		t.Fatalf("PublishTemplate (external): %v", err)
	}

	// Wait for the real, observable adoption effect.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := jm.GetJob(knownJob.ID); !ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, ok := jm.GetJob(knownJob.ID); ok {
		t.Fatal("expected the superior relayed template to replace the pre-existing job (old job id still resolvable)")
	}

	// The relay adoption itself must have cost NO local daemon call.
	if got := node.templateCalls.Load(); got != 1 {
		t.Fatalf("relay adoption cost %d local GetBlockTemplate calls; want 0 (templateCalls should still be 1)", got-1)
	}

	// (a) The already-KNOWN session was reseeded from the relayed content,
	// and kept its OWN stamped difficulty across the adoption.
	reseeded, err := jm.JobForSessionAtDifficulty(context.Background(), "aaaa", 321)
	if err != nil {
		t.Fatalf("JobForSessionAtDifficulty (known session, post-adopt): %v", err)
	}
	if reseeded.Height != 51 {
		t.Errorf("known session: Height = %d, want the adopted relayed template's 51", reseeded.Height)
	}
	if reseeded.StaticDifficulty != 321 {
		t.Errorf("known session: StaticDifficulty = %d after relay adoption, want its own preserved 321", reseeded.StaticDifficulty)
	}

	// (b) A brand-NEW session, never seen before the adoption, must ALSO
	// derive from the relay-adopted shared template -- with no local
	// daemon call. This is the gap this fix closes.
	fresh, err := jm.JobForSessionAtDifficulty(context.Background(), "zzzz", 654)
	if err != nil {
		t.Fatalf("JobForSessionAtDifficulty (brand-new session, post-adopt): %v", err)
	}
	if fresh.Height != 51 {
		t.Errorf("brand-new session: Height = %d, want the adopted relayed template's 51", fresh.Height)
	}
	if fresh.StaticDifficulty != 654 {
		t.Errorf("brand-new session: StaticDifficulty = %d, want its own requested 654", fresh.StaticDifficulty)
	}
	if fresh.ID == reseeded.ID {
		t.Error("the brand-new session and the known session must still get DISTINCT Job.IDs")
	}
	if got := node.templateCalls.Load(); got != 1 {
		t.Errorf("serving both a known and a brand-new sessionKey from the relay-adopted template cost %d additional local GetBlockTemplate calls; want 0", got-1)
	}
}

// TestTariAlgosKeepPerSessionIndependentTemplateFetch is the explicit
// SCOPE-GUARD for this fix: it proves every Tari algo
// (SHA3X/C29/RXT) still gets its OWN independent GetBlockTemplate
// call per newly-seen session, i.e. that this fix genuinely did NOT change
// Tari behavior.
//
// RXT in particular MUST keep this behavior for real correctness, not
// merely for compatibility: RXT is RandomX-family
// (trust.go's IsRandomXFamily), so session.go omits XN from its wire
// job payload and SKIPS the submit-time xn nonce-prefix check
// entirely for it -- per-fetch coinbase_extra randomization
// (node.go's buildCoinbaseExtra) is therefore the ONLY thing giving
// two ordinary RXT sessions genuinely different search spaces. See
// JobManager.usesSharedTemplate's doc comment for the full per-algo
// analysis.
func TestTariAlgosKeepPerSessionIndependentTemplateFetch(t *testing.T) {
	for _, algo := range []poolpb.Algo{
		poolpb.Algo_ALGO_SHA3X,
		poolpb.Algo_ALGO_C29,
		poolpb.Algo_ALGO_RXT,
	} {
		algo := algo
		t.Run(algoWireName(algo), func(t *testing.T) {
			node := &fakeNodeClient{height: 42, mergeMiningHash: []byte("tari-scope-guard-merge-hash-32b")}
			jm := NewJobManager(JobManagerConfig{
				Node: node, Algo: algo, PayoutAddress: "tari-payout-address",
			})
			if jm.usesSharedTemplate() {
				t.Fatalf("algo %v must NOT use the shared-template path", algo)
			}

			jobA, err := jm.JobForSessionAtDifficulty(context.Background(), "aaaa", 100)
			if err != nil {
				t.Fatalf("JobForSessionAtDifficulty(aaaa): %v", err)
			}
			jobB, err := jm.JobForSessionAtDifficulty(context.Background(), "bbbb", 200)
			if err != nil {
				t.Fatalf("JobForSessionAtDifficulty(bbbb): %v", err)
			}

			if got := node.templateCalls.Load(); got != 2 {
				t.Errorf("expected 2 independent GetBlockTemplate calls (one per new session) for algo %v, got %d", algo, got)
			}
			if jobA.ID == jobB.ID {
				t.Error("expected different sessions to get different job ids")
			}
			if jobA == jobB {
				t.Error("expected different sessions to get distinct *Job pointers")
			}
			// Genuinely different underlying templates (distinct
			// BlockHash per real fetch), which is exactly what
			// per-fetch coinbase randomization provides on a real
			// base node.
			if string(jobA.BlockHash) == string(jobB.BlockHash) {
				t.Error("expected two independent Tari fetches to yield genuinely different templates (distinct BlockHash)")
			}
			if jobA.StaticDifficulty != 100 || jobB.StaticDifficulty != 200 {
				t.Errorf("per-session difficulties not stamped correctly: %d / %d", jobA.StaticDifficulty, jobB.StaticDifficulty)
			}
		})
	}
}

// TestSharedTemplateModeScopeMatchesMoneroFamily pins the exact algo
// scope of this fix so widening or narrowing it can never happen
// silently -- see JobManager.usesSharedTemplate's doc comment for the
// evidence behind each entry.
func TestSharedTemplateModeScopeMatchesMoneroFamily(t *testing.T) {
	shared := []poolpb.Algo{
		poolpb.Algo_ALGO_RXM,
		poolpb.Algo_ALGO_XMR,
		poolpb.Algo_ALGO_ARQ,
		poolpb.Algo_ALGO_XEQ,
		poolpb.Algo_ALGO_GRFT,
		poolpb.Algo_ALGO_SFX,
		poolpb.Algo_ALGO_ZEPH,
		poolpb.Algo_ALGO_SAL,
	}
	notShared := []poolpb.Algo{
		poolpb.Algo_ALGO_SHA3X,
		poolpb.Algo_ALGO_C29,
		poolpb.Algo_ALGO_RXT,
	}
	for _, algo := range shared {
		jm := NewJobManager(JobManagerConfig{Node: &fakeNodeClient{}, Algo: algo})
		if !jm.usesSharedTemplate() {
			t.Errorf("algo %v must use the shared-template path", algo)
		}
	}
	for _, algo := range notShared {
		jm := NewJobManager(JobManagerConfig{Node: &fakeNodeClient{}, Algo: algo})
		if jm.usesSharedTemplate() {
			t.Errorf("algo %v must NOT use the shared-template path", algo)
		}
	}
	// An unconfigured/zero-value Algo normalizes to SHA3X
	// (NewJobManager's documented backward-compatibility default), so
	// it must NOT silently opt into shared-template mode either.
	jm := NewJobManager(JobManagerConfig{Node: &fakeNodeClient{}})
	if jm.usesSharedTemplate() {
		t.Error("an unconfigured Algo (normalized to SHA3X) must NOT use the shared-template path")
	}
}
