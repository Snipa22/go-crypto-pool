// Copyright and license: see repository LICENSE (MIT).
//
//go:build randomx_cgo

package validator

// NewProxyRandomXValidator returns the RandomX validator leaf-proxy's
// real Session.handleSubmit block-find re-check should use, selected
// automatically at BUILD time by the randomx_cgo tag rather than a
// runtime flag a downstream user has to know to pass.
//
// This file (randomx_cgo build tag) is the fast path: it is compiled
// in only when the binary is built with `-tags randomx_cgo` AND
// CGO_ENABLED=1 AND a C++ toolchain is available at build time (see
// randomx_cgo.go's doc comment for the full real-dependency writeup).
// Under those conditions it returns CgoRandomXValidator, backed by
// the real C++ RandomX reference implementation via
// github.com/mining-pool/go-randomx — independently benchmarked at
// ~23.6ms/hash steady-state vs. the pure-Go fallback's ~376ms/hash
// (AMD EPYC 9R14, -benchtime=20x; see factory.go's counterpart for
// that fallback path). See factory.go for the non-cgo build's
// counterpart.
//
// The return type is *CgoRandomXValidator, which satisfies
// internal/leaflib/proxy.ShareValidator's ValidateBlobSeedResult(ctx,
// blob, seed []byte, resultHex string) (bool, error) signature exactly
// — see that interface's doc comment in
// internal/leaflib/proxy/session.go.
func NewProxyRandomXValidator() *CgoRandomXValidator {
	return NewCgoRandomXValidator()
}
