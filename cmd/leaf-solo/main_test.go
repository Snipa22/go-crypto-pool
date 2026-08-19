// Copyright and license: see repository LICENSE (MIT).
package main

import "testing"

func TestResolvePortsFallsBackToLegacySingleValueFields(t *testing.T) {
	cfg := config{listenAddress: ":4444", startingDifficulty: 10000}
	ports, err := resolvePorts(cfg)
	if err != nil {
		t.Fatalf("resolvePorts: %v", err)
	}
	if len(ports) != 1 {
		t.Fatalf("len(ports) = %d, want 1", len(ports))
	}
	if ports[0].Address != ":4444" || ports[0].Difficulty != 10000 {
		t.Errorf("got %+v, want Address=:4444 Difficulty=10000", ports[0])
	}
}

func TestResolvePortsParsesLEAFSOLOPORTS(t *testing.T) {
	cfg := config{portsRaw: ":4444:10000:low-diff,:4445:1000000:high-diff"}
	ports, err := resolvePorts(cfg)
	if err != nil {
		t.Fatalf("resolvePorts: %v", err)
	}
	if len(ports) != 2 {
		t.Fatalf("len(ports) = %d, want 2", len(ports))
	}
	if ports[0].Address != ":4444" || ports[0].Difficulty != 10000 || ports[0].PortDesc != "low-diff" {
		t.Errorf("ports[0] = %+v, want {:4444 10000 low-diff}", ports[0])
	}
	if ports[1].Address != ":4445" || ports[1].Difficulty != 1000000 || ports[1].PortDesc != "high-diff" {
		t.Errorf("ports[1] = %+v, want {:4445 1000000 high-diff}", ports[1])
	}
}

func TestResolvePortsParsesEntryWithoutDesc(t *testing.T) {
	cfg := config{portsRaw: ":4444:10000"}
	ports, err := resolvePorts(cfg)
	if err != nil {
		t.Fatalf("resolvePorts: %v", err)
	}
	if len(ports) != 1 || ports[0].Address != ":4444" || ports[0].Difficulty != 10000 || ports[0].PortDesc != "" {
		t.Errorf("got %+v, want {:4444 10000 \"\"}", ports)
	}
}

func TestResolvePortsRejectsInvalidEntries(t *testing.T) {
	cases := []string{
		":4444",
		":4444:notanumber",
		":4444:0",
		"::0:desc",
	}
	for _, raw := range cases {
		cfg := config{portsRaw: raw}
		if _, err := resolvePorts(cfg); err == nil {
			t.Errorf("resolvePorts(%q): expected an error, got nil", raw)
		}
	}
}
