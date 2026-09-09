// Copyright and license: see repository LICENSE (MIT).
package leaflib

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
)

// TestLoadOrGenerateCert_GeneratesUsableCertAndHandshakes confirms
// the primary "no cert/key files configured" path: LoadOrGenerateCert
// produces a valid tls.Certificate that a real crypto/tls handshake
// (loopback tls.Listen + tls.Dial, InsecureSkipVerify: true -- exactly
// how a real miner with cert verification disabled connects) actually
// succeeds against.
func TestLoadOrGenerateCert_GeneratesUsableCertAndHandshakes(t *testing.T) {
	logger := log.New(io.Discard, "", 0)

	cert, err := LoadOrGenerateCert("", "", "", "127.0.0.1:4444", logger)
	if err != nil {
		t.Fatalf("LoadOrGenerateCert: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatalf("expected a non-empty generated certificate chain")
	}
	if _, err := x509.ParseCertificate(cert.Certificate[0]); err != nil {
		t.Fatalf("generated certificate does not parse as valid X.509: %v", err)
	}

	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 5)
		_, err = io.ReadFull(conn, buf)
		if err != nil {
			serverDone <- err
			return
		}
		if !bytes.Equal(buf, []byte("hello")) {
			serverDone <- nil
			return
		}
		_, err = conn.Write([]byte("world"))
		serverDone <- err
	}()

	clientConn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	defer clientConn.Close()

	if _, err := clientConn.Write([]byte("hello")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	respBuf := make([]byte, 5)
	if _, err := io.ReadFull(clientConn, respBuf); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !bytes.Equal(respBuf, []byte("world")) {
		t.Fatalf("got %q, want %q", respBuf, "world")
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server side: %v", err)
	}
}

// TestLoadOrGenerateCert_LoadsExistingFilesInsteadOfGenerating
// confirms that given a real, pre-existing cert/key file pair,
// LoadOrGenerateCert loads it (rather than generating a new one) --
// verified by comparing the loaded certificate's raw bytes to the
// bytes on disk.
func TestLoadOrGenerateCert_LoadsExistingFilesInsteadOfGenerating(t *testing.T) {
	logger := log.New(io.Discard, "", 0)
	dir := t.TempDir()

	// Generate a real cert/key pair with the Go stdlib directly (not
	// via LoadOrGenerateCert -- this must be an INDEPENDENTLY
	// produced fixture) and write it to disk.
	_, certPEM, keyPEM, err := generateSelfSignedCert("existing-cert-test")
	if err != nil {
		t.Fatalf("generateSelfSignedCert (test fixture): %v", err)
	}
	certFile := filepath.Join(dir, "existing.pem")
	keyFile := filepath.Join(dir, "existing.key")
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		t.Fatalf("writing fixture cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("writing fixture key file: %v", err)
	}

	got, err := LoadOrGenerateCert(certFile, keyFile, "", "127.0.0.1:4444", logger)
	if err != nil {
		t.Fatalf("LoadOrGenerateCert: %v", err)
	}

	wantBlock, _ := pem.Decode(certPEM)
	if wantBlock == nil {
		t.Fatalf("failed to decode fixture cert PEM")
	}
	if len(got.Certificate) == 0 {
		t.Fatalf("loaded certificate has no chain")
	}
	if !bytes.Equal(got.Certificate[0], wantBlock.Bytes) {
		t.Fatalf("loaded certificate bytes do not match the on-disk fixture -- LoadOrGenerateCert appears to have generated a new cert instead of loading the existing one")
	}
}

// TestLoadOrGenerateCert_PersistsAndReloadsAcrossRestarts confirms the
// restart-stability behavior: given an empty persistPath initially
// (no existing cert), LoadOrGenerateCert (a) generates a fresh cert,
// (b) writes it out to persistPath, and (c) a SECOND call with the
// SAME persistPath (and no explicit cert/key files) reloads the SAME
// cert rather than generating a new one.
func TestLoadOrGenerateCert_PersistsAndReloadsAcrossRestarts(t *testing.T) {
	logger := log.New(io.Discard, "", 0)
	dir := t.TempDir()
	persistPath := filepath.Join(dir, "auto-generated.pem")
	certPath, keyPath := persistedPaths(persistPath)

	if fileExists(certPath) || fileExists(keyPath) {
		t.Fatalf("test precondition violated: persisted cert/key already exist before first call")
	}

	first, err := LoadOrGenerateCert("", "", persistPath, "127.0.0.1:4444", logger)
	if err != nil {
		t.Fatalf("first LoadOrGenerateCert call: %v", err)
	}
	if !fileExists(certPath) {
		t.Fatalf("expected generated cert to be persisted to %s, but it does not exist", certPath)
	}
	if !fileExists(keyPath) {
		t.Fatalf("expected generated key to be persisted to %s, but it does not exist", keyPath)
	}

	second, err := LoadOrGenerateCert("", "", persistPath, "127.0.0.1:4444", logger)
	if err != nil {
		t.Fatalf("second LoadOrGenerateCert call: %v", err)
	}

	if len(first.Certificate) == 0 || len(second.Certificate) == 0 {
		t.Fatalf("expected both calls to return a non-empty certificate chain")
	}
	if !bytes.Equal(first.Certificate[0], second.Certificate[0]) {
		t.Fatalf("second call with the same persistPath returned a DIFFERENT certificate than the first -- persistence-across-restarts is broken (the cert rotated instead of being reloaded)")
	}
}
