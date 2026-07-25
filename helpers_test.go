// Copyright 2026 Bruno Schaatsbergen. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmtls_test

// Fixtures shared by the tests.
//
// Everything runs against the TPM 2.0 reference simulator, so no TPM and no root
// are needed, and the tests run on any platform.
//
// Each test starts by playing the key's owner: an agent that creates a key
// inside the TPM and persists it at a handle. Only then does the package under
// test attach to it, which is the arrangement this package is written for.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/stretchr/testify/require"

	tpmtls "github.com/bschaatsbergen/go-tpm-tls"
)

// testHandle is in the owner hierarchy, clear of the ranges TCG reserves for the
// endorsement key (0x81010001, 0x81010002) and the storage root key
// (0x81000001). Picking one of those would pass against a simulator and collide
// on a real machine.
const testHandle = tpmtls.Handle(0x81000004)

// signingTemplate is what an agent would provision: an unrestricted ECDSA P-256
// signing key the TPM generates and will not let out.
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

// newSimulator returns a TPM that closes with the test.
func newSimulator(t *testing.T) io.ReadWriter {
	t.Helper()

	sim, err := simulator.Get()
	require.NoError(t, err, "start simulator")
	t.Cleanup(func() { sim.Close() })

	return sim
}

// agentTPM returns a TPM that already holds a key at testHandle, the way a
// machine looks once its agent has provisioned one and moved on.
func agentTPM(t *testing.T) io.ReadWriter {
	t.Helper()

	rw := newSimulator(t)
	persistKey(t, rw, testHandle, signingTemplate)

	return rw
}

// persistKey creates a key and leaves it at handle, dropping the creator's own
// reference the way an agent would.
func persistKey(t *testing.T, rw io.ReadWriter, handle tpmtls.Handle, template tpm2.Public) {
	t.Helper()

	key, err := client.NewCachedKey(rw, tpm2.HandleOwner, template, handle)
	require.NoError(t, err, "provision key at %#x", handle)
	key.Close()
}

// attach opens the key at testHandle through the package under test.
func attach(t *testing.T, rw io.ReadWriter) *tpmtls.Key {
	t.Helper()

	key, err := tpmtls.New(rw, testHandle)
	require.NoError(t, err, "attach to key")
	t.Cleanup(func() { key.Close() })

	return key
}

// digest returns n random bytes, standing in for something to sign.
func digest(t *testing.T, n int) []byte {
	t.Helper()

	d := make([]byte, n)
	_, err := rand.Read(d)
	require.NoError(t, err)

	return d
}

// testCA is a throwaway certificate authority for the TLS tests.
type testCA struct {
	cert   *x509.Certificate
	key    *ecdsa.PrivateKey
	pool   *x509.CertPool
	serial int64
}

func newCA(t *testing.T) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

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
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	return &testCA{cert: cert, key: key, pool: pool, serial: 1}
}

// issue certifies a public key for client and server auth on localhost.
func (ca *testCA) issue(t *testing.T, pub any) []byte {
	t.Helper()

	ca.serial++
	template := &x509.Certificate{
		SerialNumber: big.NewInt(ca.serial),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, pub, ca.key)
	require.NoError(t, err)

	return der
}
