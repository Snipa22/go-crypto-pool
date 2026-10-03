// Copyright and license: see repository LICENSE (MIT).
//
//go:build !randomx_cgo

package validator

// NewProxyRandomXValidator returns the RandomX validator leaf-proxy's
// real Session.handleSubmit block-find re-check should use, selected
// automatically at BUILD time by the randomx_cgo tag rather than a
// runtime flag a downstream user has to know to pass.
//
// This file (no build tag other than the inverse of randomx_cgo)
// provides the fallback: a plain `go build` with no tags (and the
// default CGO_ENABLED=0) gets the real, in-process, pure-Go
// PureGoRandomXValidator — the same cgo-free, no-external-daemon
// behavior leaf-proxy has always had. See factory_cgo.go for the
// counterpart that activates under `-tags randomx_cgo`
// (CGO_ENABLED=1), and randomx_cgo.go / randomx_puregolang.go for the
// two validators' own honest design/tradeoff writeups.
//
// The return type is *PureGoRandomXValidator, which satisfies
// internal/leaflib/proxy.ShareValidator's ValidateBlobSeedResult(ctx,
// blob, seed []byte, resultHex string) (bool, error) signature exactly
// — see that interface's doc comment in
// internal/leaflib/proxy/session.go.
func NewProxyRandomXValidator() *PureGoRandomXValidator {
	return NewPureGoRandomXValidator()
}
