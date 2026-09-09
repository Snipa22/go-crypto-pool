// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"strings"
	"testing"
)

// TestUpstreamConfig_NormalizedDefaultAgentIdentifiesAsXMRNodeProxy
// is the regression test for the live production incident this pass
// fixes: pool.supportxmr.com was IP-banning this leaf for duplicate
// share submissions because its default Agent string did NOT contain
// the literal substring "xmr-node-proxy" (nodejs-pool-sxmr's
// lib/pool.js: `agent.includes("xmr-node-proxy")`), so the pool never
// granted the advanced-client dialect and never published
// client_nonce_offset/client_pool_offset -- leaving
// WorkerTemplate.BlobForWorker (template.go) unable to give
// independent downstream miners non-colliding blobs. This is the
// deliberate INVERSE of the old invariant this same test used to
// enforce (an unconfigured Agent must NOT contain that substring);
// see UpstreamConfig.Agent's doc comment for the full rationale for
// why this default is now the opposite.
func TestUpstreamConfig_NormalizedDefaultAgentIdentifiesAsXMRNodeProxy(t *testing.T) {
	got := UpstreamConfig{}.normalized().Agent
	if !strings.Contains(got, "xmr-node-proxy") {
		t.Errorf("normalized() default Agent = %q, must contain the substring %q (see this test's doc comment)", got, "xmr-node-proxy")
	}
	if got == "" {
		t.Error("normalized() default Agent must not be empty")
	}
}

// TestUpstreamConfig_NormalizedPreservesExplicitAgent confirms an
// operator-supplied Agent (whether or not it contains
// "xmr-node-proxy") is passed through unchanged -- normalized() only
// ever fills in a default when Agent is the empty string.
func TestUpstreamConfig_NormalizedPreservesExplicitAgent(t *testing.T) {
	const explicit = "some-other-agent/1.2.3"
	got := UpstreamConfig{Agent: explicit}.normalized().Agent
	if got != explicit {
		t.Errorf("normalized() Agent = %q, want unchanged explicit value %q", got, explicit)
	}
}
