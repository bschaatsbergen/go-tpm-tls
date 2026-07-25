// Copyright 2026 Bruno Schaatsbergen. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmtls_test

// Tests run against the TPM 2.0 reference simulator, so they need no TPM and no
// root, and run on any platform.
//
// Each test starts by playing the key's owner: an agent that creates a key
// inside the TPM and persists it at a handle. Only then does the package under
// test attach to it, which is the arrangement this package is written for. A
// test that created its own key would be testing a scenario that never happens.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"

	"github.com/bschaatsbergen/go-tpm-tls"
)

// testHandle is in the owner hierarchy, clear of the ranges TCG reserves for
// the endorsement key (0x81010001, 0x81010002) and the storage root key
// (0x81000001). Picking one of those would have the tests pass against a
// simulator and collide on a real machine.
const testHandle = tpmtls.Handle(0x81000004)

var signingTemplate = tpm2.Public{
	Type:    tpm2.AlgECC,
	NameAlg: tpm2.AlgSHA256,
	Attributes: tpm2.FlagSign | tpm2.FlagSensitiveDataOrigin |
		tpm2.FlagUserWithAuth | tpm2.FlagFixedTPM | tpm2.FlagFixedParent,
	ECCParameters: &tpm2.ECCParams{
		Sign:    &tpm2.SigScheme{Alg: tpm2.AlgECDSA, Hash: tpm2.AlgSHA256},
		CurveID: tpm2.CurveNISTP256,
	},
}

// agentTPM stands in for a machine whose TPM already holds a key. It creates one
// and persists it at testHandle, then drops its own reference, which is what an
// agent does once the key is provisioned: the key outlives the process that made
// it.
func agentTPM(t *testing.T) io.ReadWriter {
	t.Helper()
	sim, err := simulator.Get()
	if err != nil {
		t.Fatalf("start simulator: %v", err)
	}
	t.Cleanup(func() { sim.Close() })

	owner, err := client.NewCachedKey(sim, tpm2.HandleOwner, signingTemplate, testHandle)
	if err != nil {
		t.Fatalf("agent could not create its key: %v", err)
	}
	owner.Close()
	return sim
}

func attach(t *testing.T, rw io.ReadWriter) *tpmtls.Key {
	t.Helper()
	key, err := tpmtls.New(rw, testHandle)
	if err != nil {
		t.Fatalf("attach to existing key: %v", err)
	}
	t.Cleanup(func() { key.Close() })
	return key
}

func TestAttachesToAnExistingKey(t *testing.T) {
	key := attach(t, agentTPM(t))

	if key.Handle() != testHandle {
		t.Fatalf("expected handle %#x, got %#x", testHandle, key.Handle())
	}
	if _, ok := key.Public().(*ecdsa.PublicKey); !ok {
		t.Fatalf("expected an ECDSA public key, got %T", key.Public())
	}
}

func TestUnknownHandleFails(t *testing.T) {
	rw := agentTPM(t)

	if _, err := tpmtls.New(rw, tpmtls.Handle(0x81FFFFFF)); err == nil {
		t.Fatal("attaching to a handle with no key must fail")
	}
}

func TestKeyIsNonExportable(t *testing.T) {
	key := attach(t, agentTPM(t))

	fixed, err := key.NonExportable()
	if err != nil {
		t.Fatal(err)
	}
	if !fixed {
		t.Fatal("the TPM must report the key as fixed to this TPM")
	}
}

func TestSignVerifies(t *testing.T) {
	key := attach(t, agentTPM(t))

	digest := make([]byte, 32)
	if _, err := rand.Read(digest); err != nil {
		t.Fatal(err)
	}
	sig, err := key.Sign(rand.Reader, digest, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(key.Public().(*ecdsa.PublicKey), digest, sig) {
		t.Fatal("signature from the TPM must verify under its public key")
	}
}

func TestSignIsSafeForConcurrentUse(t *testing.T) {
	key := attach(t, agentTPM(t))

	digest := make([]byte, 32)
	if _, err := rand.Read(digest); err != nil {
		t.Fatal(err)
	}
	const n = 8
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := key.Sign(rand.Reader, digest, nil)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent signing must be serialized, not fail: %v", err)
		}
	}
}

// TestCloseLeavesTheKeyInPlace matters because the key belongs to somebody else.
// A workload finishing its work must not take the machine's identity with it,
// which would be a rather abrupt way to break every other workload on the box.
func TestCloseLeavesTheKeyInPlace(t *testing.T) {
	rw := agentTPM(t)

	first, err := tpmtls.New(rw, testHandle)
	if err != nil {
		t.Fatal(err)
	}
	publicBefore := first.Public().(*ecdsa.PublicKey)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second, err := tpmtls.New(rw, testHandle)
	if err != nil {
		t.Fatalf("the key must still be there after Close: %v", err)
	}
	defer second.Close()
	if !second.Public().(*ecdsa.PublicKey).Equal(publicBefore) {
		t.Fatal("the same key must be at the handle")
	}
}

func TestSignAfterCloseFails(t *testing.T) {
	key := attach(t, agentTPM(t))

	if err := key.Close(); err != nil {
		t.Fatal(err)
	}
	if err := key.Close(); err != nil {
		t.Fatalf("Close must be safe to call twice: %v", err)
	}
	if _, err := key.Sign(rand.Reader, make([]byte, 32), nil); err == nil {
		t.Fatal("signing with a closed key must fail")
	}
}

func TestCertificateRequestProvesPossession(t *testing.T) {
	key := attach(t, agentTPM(t))

	der, err := key.CertificateRequest(nil)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("the CSR self signature must verify: %v", err)
	}
	if !csr.PublicKey.(*ecdsa.PublicKey).Equal(key.Public()) {
		t.Fatal("the CSR must carry this key's public half")
	}
}

func TestMutualTLSHandshake(t *testing.T) {
	key := attach(t, agentTPM(t))

	ca, caKey := newCA(t)
	clientDER := issue(t, ca, caKey, key.Public())
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverDER := issue(t, ca, caKey, &serverKey.PublicKey)
	pool := x509.NewCertPool()
	pool.AddCert(ca)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	type serverResult struct {
		peer *x509.Certificate
		err  error
	}
	results := make(chan serverResult, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			results <- serverResult{err: err}
			return
		}
		defer conn.Close()
		server := tls.Server(conn, &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{{Certificate: [][]byte{serverDER}, PrivateKey: serverKey}},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    pool,
		})
		if err := server.Handshake(); err != nil {
			results <- serverResult{err: err}
			return
		}
		_, _ = server.Write([]byte("ok"))
		_ = server.CloseWrite()
		results <- serverResult{peer: server.ConnectionState().PeerCertificates[0]}
	}()

	client, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{key.TLSCertificate(clientDER)},
		RootCAs:      pool,
		ServerName:   "localhost",
	})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	body, err := io.ReadAll(client)
	client.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "ok" {
		t.Fatalf("expected the server to answer, got %q", body)
	}

	got := <-results
	if got.err != nil {
		t.Fatalf("server: %v", got.err)
	}
	if !got.peer.PublicKey.(*ecdsa.PublicKey).Equal(key.Public()) {
		t.Fatal("the server must have authenticated the TPM key")
	}
}

func newCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tpmtls test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

var serial int64 = 1

func issue(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, pub any) []byte {
	t.Helper()
	serial++
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, pub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestHandlesListsPersistentKeys(t *testing.T) {
	rw := agentTPM(t)

	handles, err := tpmtls.PersistentHandles(rw)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, h := range handles {
		if h == testHandle {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected %#x among %v", testHandle, handles)
	}
}

// TestFindHandleByPublicKey covers the way out of hardcoding a handle: the
// certificate a workload is about to present identifies the key to sign with,
// so the provisioning decision stays on the machine that made it.
func TestFindHandleByPublicKey(t *testing.T) {
	rw := agentTPM(t)
	key := attach(t, rw)

	handle, err := tpmtls.FindHandle(rw, key.Public())
	if err != nil {
		t.Fatal(err)
	}
	if handle != testHandle {
		t.Fatalf("expected %#x, got %#x", testHandle, handle)
	}
}

func TestFindHandleUnknownKey(t *testing.T) {
	rw := agentTPM(t)

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tpmtls.FindHandle(rw, &other.PublicKey); !errors.Is(err, tpmtls.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestNewForCertificate(t *testing.T) {
	rw := agentTPM(t)
	key := attach(t, rw)

	ca, caKey := newCA(t)
	certDER := issue(t, ca, caKey, key.Public())
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	fromCert, err := tpmtls.NewForCertificate(rw, cert)
	if err != nil {
		t.Fatal(err)
	}
	defer fromCert.Close()
	if fromCert.Handle() != testHandle {
		t.Fatalf("expected %#x, got %#x", testHandle, fromCert.Handle())
	}
}
