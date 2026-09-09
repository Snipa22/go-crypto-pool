// Copyright and license: see repository LICENSE (MIT).
package leaflib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"
)

// LoadOrGenerateCert is the ONE shared cert-provisioning helper behind
// every leaf binary's optional TLS listener support (leaf-solo,
// leaf-direct, leaf-proxy). It deliberately mirrors the real
// nodejs-pool-sxmr reference's lib/pool.js design exactly: a per-port
// boolean `ssl` field gates whether a given listener is wrapped with
// `tls.createServer({key, cert}, socketConn)` or left as a plain
// `net.createServer(socketConn)` -- ONE shared cert/key pair for the
// whole process, not per-port certs. The miner-protocol connection
// handler on the Go side of this repo (solo.Server.Serve/handleConn,
// proxy.Server.Serve/handleConn) is IDENTICAL either way; TLS is
// purely a listener/accept-layer concern applied at the call site in
// each cmd/leaf-*/main.go, never inside those Serve/handleConn
// functions themselves.
//
// Alex's exact framing for why this is safe and sufficient (verbatim,
// see this repo's PR history for the same quote):
//
//	"The miners don't verify the certs, so self-sign is fine, it's
//	just to send traffic that looks like https on 443."
//
// This is NOT a certificate-trust feature. Self-signing here is
// intentional, not a shortcut or a placeholder for "real" CA/Let's
// Encrypt integration later -- there is no real-hostname requirement,
// no cert pinning, and miners are expected to connect with TLS
// verification disabled client-side (mirroring xmrig's own `--tls`
// flag with no cert pinning by default). The entire purpose is
// wire-shape disguise: making mining traffic look like ordinary HTTPS
// on port 443 for firewalls/DPI that only permit 443-shaped outbound
// traffic. Do NOT build any CA/Let's Encrypt integration on top of
// this function -- that is explicitly out of scope.
//
// Behavior: if certFile and keyFile are both non-empty AND both files
// exist on disk, they are loaded verbatim via tls.LoadX509KeyPair and
// returned -- an operator-supplied cert always wins. Otherwise, a
// fresh, real, self-signed ECDSA P-256 X.509 certificate is generated
// in memory (RSA is not needed for this use case: no client validates
// the cert, and ECDSA P-256 is cheaper to generate and smaller on the
// wire), valid for ~1 year, with a generic CN (bindAddress if
// non-empty, else "localhost") -- this CN is never actually checked
// by a real client, since miners connect with certificate
// verification disabled.
//
// Persistence: if persistPath is non-empty AND a cert was
// auto-generated (i.e. certFile/keyFile were not both supplied and
// present), the generated cert+key are ALSO written out (PEM cert,
// PEM key, same file, cert first then key) to persistPath so restarts
// don't rotate the cert. This is a deliberate choice: even though
// miners never validate the cert, silently rotating it on every
// restart is still needless log noise / a mild surprise for an
// operator who pokes at the live cert with openssl. If persistPath is
// empty, persistence is skipped entirely and the self-signed cert
// lives only in memory for this process's lifetime -- it WILL change
// on every restart. On a subsequent call with the same persistPath
// and no explicit certFile/keyFile, a previously persisted cert is
// loaded from persistPath instead of generating a new one.
//
// Logs clearly via logger which path was taken: loaded from
// certFile/keyFile, loaded from a previously persisted persistPath,
// or freshly auto-generated (and, in that last case, whether it was
// persisted or will rotate on next restart).
func LoadOrGenerateCert(certFile, keyFile, persistPath, bindAddress string, logger *log.Logger) (tls.Certificate, error) {
	if certFile != "" && keyFile != "" {
		if fileExists(certFile) && fileExists(keyFile) {
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return tls.Certificate{}, fmt.Errorf("leaflib: loading TLS cert/key pair (%s, %s): %w", certFile, keyFile, err)
			}
			logPrintf(logger, "TLS: loaded cert/key pair from %s / %s", certFile, keyFile)
			return cert, nil
		}
	}

	// No explicit, on-disk cert/key pair configured. If a persisted
	// self-signed cert already exists at persistPath (from an earlier
	// run of this same process), reload it instead of generating a
	// new one -- this is what makes the cert stable across restarts.
	if persistPath != "" {
		certPath, keyPath := persistedPaths(persistPath)
		if fileExists(certPath) && fileExists(keyPath) {
			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				return tls.Certificate{}, fmt.Errorf("leaflib: loading previously persisted self-signed TLS cert/key pair (%s, %s): %w", certPath, keyPath, err)
			}
			logPrintf(logger, "TLS: loaded previously persisted self-signed cert from %s / %s", certPath, keyPath)
			return cert, nil
		}
	}

	cert, certPEM, keyPEM, err := generateSelfSignedCert(bindAddress)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("leaflib: generating self-signed TLS cert: %w", err)
	}

	if persistPath == "" {
		logPrintf(logger, "TLS: generated a new self-signed cert in memory (no -tls-cert-persist-path configured -- this cert will be regenerated, i.e. rotate, on next restart)")
		return cert, nil
	}

	certPath, keyPath := persistedPaths(persistPath)
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, fmt.Errorf("leaflib: persisting generated TLS cert to %s: %w", certPath, err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, fmt.Errorf("leaflib: persisting generated TLS key to %s: %w", keyPath, err)
	}
	logPrintf(logger, "TLS: generated a new self-signed cert and persisted it to %s / %s (restarts will reload it instead of rotating it)", certPath, keyPath)
	return cert, nil
}

// persistedPaths derives the on-disk cert and key file paths from a
// single persistPath: persistPath is used verbatim as the cert file,
// and persistPath+".key" as the key file. This keeps
// LoadOrGenerateCert's public signature to a single path parameter
// (matching the brief's "persistPath" wording) while still writing
// out two real, separate PEM files (cert / key) rather than
// concatenating both into one file.
func persistedPaths(persistPath string) (certPath, keyPath string) {
	return persistPath, persistPath + ".key"
}

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func logPrintf(logger *log.Logger, format string, args ...any) {
	if logger == nil {
		return
	}
	logger.Printf(format, args...)
}

// generateSelfSignedCert creates a real, self-signed ECDSA P-256
// X.509 certificate valid for ~1 year, with a generic CN derived from
// bindAddress (falling back to "localhost" if bindAddress is empty).
// Returns the parsed tls.Certificate (ready to hand to
// tls.Config.Certificates) alongside the PEM-encoded cert and key
// bytes (for optional on-disk persistence by the caller).
func generateSelfSignedCert(bindAddress string) (cert tls.Certificate, certPEM, keyPEM []byte, err error) {
	cn := bindAddress
	if cn == "" {
		cn = "localhost"
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("generating ECDSA P-256 key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("generating certificate serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"go-crypto-pool leaf (self-signed, not for trust)"}},
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{cn},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("creating self-signed certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("marshaling ECDSA private key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert, err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("parsing freshly generated cert/key pair: %w", err)
	}
	return cert, certPEM, keyPEM, nil
}
