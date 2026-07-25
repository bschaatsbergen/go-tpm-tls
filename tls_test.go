// Copyright 2026 Bruno Schaatsbergen. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmtls_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tpmtls "github.com/bschaatsbergen/go-tpm-tls"
)

func TestTLSCertificateCarriesTheChain(t *testing.T) {
	key := attach(t, agentTPM(t))
	leaf := []byte{1, 2, 3}

	cert := key.TLSCertificate(leaf)

	assert.Equal(t, [][]byte{leaf}, cert.Certificate)
}

// crypto/tls asks the PrivateKey field to sign, so the key has to be there
// rather than any material copied out of it.
func TestTLSCertificateSignsWithTheKey(t *testing.T) {
	key := attach(t, agentTPM(t))

	cert := key.TLSCertificate([]byte{1})

	assert.Same(t, key, cert.PrivateKey)
}

func TestCertificateRequestSelfSignatureVerifies(t *testing.T) {
	key := attach(t, agentTPM(t))

	der, err := key.CertificateRequest(nil)

	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	assert.NoError(t, csr.CheckSignature())
}

func TestCertificateRequestCarriesThePublicKey(t *testing.T) {
	key := attach(t, agentTPM(t))

	der, err := key.CertificateRequest(nil)

	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	assert.Equal(t, key.Public(), csr.PublicKey)
}

// peer is what a server learned about the client it just authenticated.
type peer struct {
	cert *x509.Certificate
	body string
	err  error
}

// handshake runs one mutually authenticated connection over a real socket, with
// the server requiring and verifying a client certificate.
func handshake(t *testing.T, key *tpmtls.Key, ca *testCA, clientDER []byte) peer {
	t.Helper()

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serverDER := ca.issue(t, &serverKey.PublicKey)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	results := make(chan peer, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			results <- peer{err: err}
			return
		}
		defer conn.Close()

		server := tls.Server(conn, &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{{Certificate: [][]byte{serverDER}, PrivateKey: serverKey}},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    ca.pool,
		})
		if err := server.Handshake(); err != nil {
			results <- peer{err: err}
			return
		}
		_, _ = server.Write([]byte("ok"))
		_ = server.CloseWrite()
		results <- peer{cert: server.ConnectionState().PeerCertificates[0]}
	}()

	client, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{key.TLSCertificate(clientDER)},
		RootCAs:      ca.pool,
		ServerName:   "localhost",
	})
	if err != nil {
		return peer{err: err}
	}
	body, err := io.ReadAll(client)
	client.Close()

	got := <-results
	got.body = string(body)
	if got.err == nil {
		got.err = err
	}

	return got
}

func TestHandshakeSucceedsWithATPMKey(t *testing.T) {
	key := attach(t, agentTPM(t))
	ca := newCA(t)

	got := handshake(t, key, ca, ca.issue(t, key.Public()))

	assert.NoError(t, got.err)
}

func TestHandshakeAuthenticatesTheTPMKey(t *testing.T) {
	key := attach(t, agentTPM(t))
	ca := newCA(t)

	got := handshake(t, key, ca, ca.issue(t, key.Public()))

	require.NoError(t, got.err)
	assert.Equal(t, key.Public(), got.cert.PublicKey)
}

func TestHandshakeCarriesApplicationData(t *testing.T) {
	key := attach(t, agentTPM(t))
	ca := newCA(t)

	got := handshake(t, key, ca, ca.issue(t, key.Public()))

	require.NoError(t, got.err)
	assert.Equal(t, "ok", got.body)
}

// Curves other than P-256 complete a handshake too, not just a raw signature.
func TestHandshakeSucceedsOnP384(t *testing.T) {
	rw := newSimulator(t)
	template := signingTemplate
	template.NameAlg = tpm2.AlgSHA384
	template.ECCParameters = &tpm2.ECCParams{
		Sign:    &tpm2.SigScheme{Alg: tpm2.AlgECDSA, Hash: tpm2.AlgSHA384},
		CurveID: tpm2.CurveNISTP384,
	}
	persistKey(t, rw, testHandle, template)
	key := attach(t, rw)
	ca := newCA(t)

	got := handshake(t, key, ca, ca.issue(t, key.Public()))

	assert.NoError(t, got.err)
}
