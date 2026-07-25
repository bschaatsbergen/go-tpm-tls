// Copyright 2026 Bruno Schaatsbergen. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmtls_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tpmtls "github.com/bschaatsbergen/go-tpm-tls"
)

func TestPersistentHandlesFindsTheProvisionedKey(t *testing.T) {
	rw := agentTPM(t)

	handles, err := tpmtls.PersistentHandles(rw)

	require.NoError(t, err)
	assert.Contains(t, handles, testHandle)
}

func TestPersistentHandlesIsEmptyOnAFreshTPM(t *testing.T) {
	rw := newSimulator(t)

	handles, err := tpmtls.PersistentHandles(rw)

	require.NoError(t, err)
	assert.Empty(t, handles)
}

// The way out of hardcoding a handle: the certificate a workload is about to
// present says which key in the TPM to sign with.
func TestFindHandleLocatesAKeyByItsPublicHalf(t *testing.T) {
	rw := agentTPM(t)
	key := attach(t, rw)

	handle, err := tpmtls.FindHandle(rw, key.Public())

	require.NoError(t, err)
	assert.Equal(t, testHandle, handle)
}

func TestFindHandleReportsNotFoundForAnUnknownKey(t *testing.T) {
	rw := agentTPM(t)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, err = tpmtls.FindHandle(rw, &other.PublicKey)

	assert.ErrorIs(t, err, tpmtls.ErrNotFound)
}

func TestFindHandleRejectsAKeyItCannotCompare(t *testing.T) {
	rw := agentTPM(t)

	_, err := tpmtls.FindHandle(rw, "not a key")

	assert.ErrorContains(t, err, "cannot be compared")
}

func TestNewForCertificateResolvesTheKey(t *testing.T) {
	rw := agentTPM(t)
	key := attach(t, rw)
	ca := newCA(t)
	cert, err := x509.ParseCertificate(ca.issue(t, key.Public()))
	require.NoError(t, err)

	fromCert, err := tpmtls.NewForCertificate(rw, cert)

	require.NoError(t, err)
	defer fromCert.Close()
	assert.Equal(t, testHandle, fromCert.Handle())
}

func TestNewForCertificateFailsForAnUnknownKey(t *testing.T) {
	rw := agentTPM(t)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := newCA(t)
	cert, err := x509.ParseCertificate(ca.issue(t, &other.PublicKey))
	require.NoError(t, err)

	_, err = tpmtls.NewForCertificate(rw, cert)

	assert.ErrorIs(t, err, tpmtls.ErrNotFound)
}
