package main

import (
	"testing"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

func TestParseNetwork(t *testing.T) {
	cases := []struct {
		raw     string
		want    poolpb.Network
		wantErr bool
	}{
		{raw: "mainnet", want: poolpb.Network_NETWORK_MAINNET},
		{raw: "MAINNET", want: poolpb.Network_NETWORK_MAINNET},
		{raw: "MainNet", want: poolpb.Network_NETWORK_MAINNET},
		{raw: " mainnet ", want: poolpb.Network_NETWORK_MAINNET},
		{raw: "testnet", want: poolpb.Network_NETWORK_TESTNET},
		{raw: "TESTNET", want: poolpb.Network_NETWORK_TESTNET},
		{raw: "", wantErr: true},
		{raw: "regtest", wantErr: true},
		{raw: "main", wantErr: true},
	}

	for _, c := range cases {
		t.Run(c.raw, func(t *testing.T) {
			got, err := parseNetwork(c.raw)
			if c.wantErr {
				if err == nil {
					t.Fatalf("parseNetwork(%q) = %v, nil; want error", c.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseNetwork(%q) unexpected error: %v", c.raw, err)
			}
			if got != c.want {
				t.Fatalf("parseNetwork(%q) = %v, want %v", c.raw, got, c.want)
			}
		})
	}
}
