// Copyright 2026 Bruno Schaatsbergen. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmtls_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"sync"
	"testing"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tpmtls "github.com/bschaatsbergen/go-tpm-tls"
)

func TestNewAttachesAtTheGivenHandle(t *testing.T) {
	key := attach(t, agentTPM(t))

	assert.Equal(t, testHandle, key.Handle())
}

func TestNewReturnsTheKeysPublicHalf(t *testing.T) {
	key := attach(t, agentTPM(t))

	assert.IsType(t, &ecdsa.PublicKey{}, key.Public())
}

func TestNewFailsOnAnEmptyHandle(t *testing.T) {
	rw := agentTPM(t)

	_, err := tpmtls.New(rw, tpmtls.Handle(0x81FFFFFF))

	assert.Error(t, err)
}

// A restricted key, which is what an attestation key is, only signs digests the
// TPM produced. A TLS transcript comes from the peer, so the failure belongs at
// attach rather than at the first handshake.
func TestNewFailsOnARestrictedKey(t *testing.T) {
	rw := newSimulator(t)
	const handle = tpmtls.Handle(0x81000005)
	persistKey(t, rw, handle, client.AKTemplateECC())

	_, err := tpmtls.New(rw, handle)

	assert.ErrorContains(t, err, "cannot sign")
}

// Nothing requires the key to be persistent. A transient handle resolves too,
// though only over the transport that created it.
func TestNewAttachesToATransientKey(t *testing.T) {
	rw := newSimulator(t)
	transient, err := client.NewKey(rw, tpm2.HandleOwner, signingTemplate)
	require.NoError(t, err)
	defer transient.Close()

	key, err := tpmtls.New(rw, transient.Handle())

	require.NoError(t, err)
	defer key.Close()
	assert.Equal(t, transient.Handle(), key.Handle())
}

func TestNonExportableReportsWhatTheTPMEnforces(t *testing.T) {
	key := attach(t, agentTPM(t))

	fixed, err := key.NonExportable()

	require.NoError(t, err)
	assert.True(t, fixed, "the TPM should hold this key fixed to itself")
}

func TestSignProducesAVerifiableSignature(t *testing.T) {
	key := attach(t, agentTPM(t))
	d := digest(t, 32)

	sig, err := key.Sign(rand.Reader, d, crypto.SHA256)

	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(key.Public().(*ecdsa.PublicKey), d, sig))
}

// Every curve the TPM offers works. The digest size follows the key's scheme,
// since the TPM rejects a digest that is not the size the scheme expects.
func TestSignProducesAVerifiableSignatureOnEveryCurve(t *testing.T) {
	for _, tc := range []struct {
		name    string
		nameAlg tpm2.Algorithm
		hash    crypto.Hash
		curve   tpm2.EllipticCurve
		digest  int
	}{
		{"P-256", tpm2.AlgSHA256, crypto.SHA256, tpm2.CurveNISTP256, 32},
		{"P-384", tpm2.AlgSHA384, crypto.SHA384, tpm2.CurveNISTP384, 48},
		{"P-521", tpm2.AlgSHA512, crypto.SHA512, tpm2.CurveNISTP521, 64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rw := newSimulator(t)
			template := signingTemplate
			template.NameAlg = tc.nameAlg
			template.ECCParameters = &tpm2.ECCParams{
				Sign:    &tpm2.SigScheme{Alg: tpm2.AlgECDSA, Hash: tc.nameAlg},
				CurveID: tc.curve,
			}
			persistKey(t, rw, testHandle, template)
			key := attach(t, rw)
			d := digest(t, tc.digest)

			sig, err := key.Sign(rand.Reader, d, tc.hash)

			require.NoError(t, err)
			assert.True(t, ecdsa.VerifyASN1(key.Public().(*ecdsa.PublicKey), d, sig))
		})
	}
}

// FlagFixedTPM is what makes a TPM key worth having, but this package does not
// require it: a key that can be duplicated still attaches and still signs.
// NonExportable is where the difference shows, which is why it reads the
// attributes from the TPM instead of assuming.
func TestNewAcceptsAKeyThatIsNotFixedToTheTPM(t *testing.T) {
	rw := newSimulator(t)
	template := signingTemplate
	template.Attributes = tpm2.FlagSign | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth
	persistKey(t, rw, testHandle, template)

	key, err := tpmtls.New(rw, testHandle)

	require.NoError(t, err)
	defer key.Close()
	fixed, err := key.NonExportable()
	require.NoError(t, err)
	assert.False(t, fixed, "this key can leave the TPM, and NonExportable should say so")
}

// A TPM handles one command at a time, so the package serializes signing.
// Without that, parallel handshakes would interleave commands on the transport.
func TestSignIsSafeForConcurrentUse(t *testing.T) {
	key := attach(t, agentTPM(t))
	d := digest(t, 32)

	const n = 8
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = key.Sign(rand.Reader, d, crypto.SHA256)
		}(i)
	}
	wg.Wait()

	for _, err := range errs {
		assert.NoError(t, err)
	}
}

func TestSignFailsAfterClose(t *testing.T) {
	key := attach(t, agentTPM(t))
	require.NoError(t, key.Close())

	_, err := key.Sign(rand.Reader, digest(t, 32), crypto.SHA256)

	assert.ErrorContains(t, err, "closed")
}

func TestCloseIsIdempotent(t *testing.T) {
	key := attach(t, agentTPM(t))

	require.NoError(t, key.Close())

	assert.NoError(t, key.Close())
}

// The key belongs to whoever created it. A workload finishing its work must not
// take the machine's identity with it.
func TestCloseLeavesTheKeyInPlace(t *testing.T) {
	rw := agentTPM(t)
	first, err := tpmtls.New(rw, testHandle)
	require.NoError(t, err)
	before := first.Public()
	require.NoError(t, first.Close())

	second, err := tpmtls.New(rw, testHandle)

	require.NoError(t, err)
	defer second.Close()
	assert.Equal(t, before, second.Public())
}

// A limitation rather than a feature. TLS signs with RSA-PSS at a salt length
// equal to the hash length, the TPM picks the salt length itself, and
// translating between them would produce a signature the peer rejects. If this
// ever starts passing, the README should say RSA works.
func TestRSAIsNotUsableForTLS(t *testing.T) {
	rw := newSimulator(t)
	const handle = tpmtls.Handle(0x81000007)
	persistKey(t, rw, handle, tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagSign | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagFixedTPM | tpm2.FlagFixedParent,
		RSAParameters: &tpm2.RSAParams{
			Sign:    &tpm2.SigScheme{Alg: tpm2.AlgRSAPSS, Hash: tpm2.AlgSHA256},
			KeyBits: 2048,
		},
	})
	key, err := tpmtls.New(rw, handle)
	require.NoError(t, err)
	defer key.Close()

	// The options crypto/tls passes for an RSA-PSS scheme.
	_, err = key.Sign(rand.Reader, digest(t, 32), &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})

	assert.Error(t, err)
}
