// Copyright 2026 Bruno Schaatsbergen. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmtls

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	"github.com/google/go-tpm/legacy/tpm2"
)

// ErrNotFound is returned when no persistent key in the TPM matches. Test for
// it with errors.Is: it usually means the agent has not provisioned a key yet,
// or provisioned a different one than the certificate you are holding.
var ErrNotFound = errors.New("tpmtls: no persistent key matches")

// handlesPerQuery is how many handles to ask the TPM for at a time. TPMs hold
// far fewer persistent objects than this in practice, so the loop in
// PersistentHandles almost always runs once, but the TPM is free to return
// fewer than asked and set moreData, so we page anyway.
const handlesPerQuery = 64

// PersistentHandles lists the persistent handles present in the TPM, for when
// you want to see what a machine actually holds rather than guess.
func PersistentHandles(rw io.ReadWriter) ([]Handle, error) {
	var handles []Handle

	// GetCapability walks handles in increasing order from a starting property,
	// so we resume from one past the last handle we saw until the TPM stops
	// telling us there is more.
	next := uint32(tpm2.PersistentFirst)
	for {
		values, more, err := tpm2.GetCapability(rw, tpm2.CapabilityHandles, handlesPerQuery, next)
		if err != nil {
			return nil, fmt.Errorf("tpmtls: list persistent handles: %w", err)
		}

		for _, v := range values {
			h, ok := v.(Handle)
			// The TPM answers a handle query with handles, so the assertion
			// should always hold. Skipping anything else, and anything outside
			// the persistent range, keeps a surprising TPM from confusing the
			// caller.
			if !ok || h < Handle(tpm2.PersistentFirst) || h > Handle(tpm2.PersistentLast) {
				continue
			}
			handles = append(handles, h)
		}

		// Nothing usable came back, so there is nowhere to resume from even if
		// the TPM claims otherwise.
		if !more || len(handles) == 0 {
			return handles, nil
		}
		next = uint32(handles[len(handles)-1]) + 1
	}
}

// FindHandle returns the handle of the persistent key whose public half is pub,
// or ErrNotFound.
//
// This is how a workload avoids being configured with a handle. The handle a key
// sits at is a provisioning decision made by whoever created it, and baking that
// number into an application couples the application to how one machine happened
// to be set up. But the application already holds the certificate it is about to
// present, and the public key in that certificate says exactly which key in the
// TPM to sign with.
func FindHandle(rw io.ReadWriter, pub crypto.PublicKey) (Handle, error) {
	// crypto.PublicKey is an empty interface, but every key type in the standard
	// library carries an Equal method. Asking for it beats type switching over
	// ECDSA, RSA and Ed25519 by hand, and works for key types we have not
	// thought about.
	want, ok := pub.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return 0, fmt.Errorf("tpmtls: public key of type %T cannot be compared", pub)
	}

	handles, err := PersistentHandles(rw)
	if err != nil {
		return 0, err
	}

	for _, h := range handles {
		area, _, _, err := tpm2.ReadPublic(rw, h)
		if err != nil {
			// Not readable. Some other object we have no business with, so move
			// on rather than failing the whole search.
			continue
		}
		got, err := area.Key()
		if err != nil {
			// A persistent object that is not a key we can express as a
			// crypto.PublicKey, an NV index or a symmetric key for instance.
			continue
		}
		if want.Equal(got) {
			return h, nil
		}
	}

	return 0, ErrNotFound
}

// NewForCertificate attaches to the key matching the certificate's public key,
// over an already open TPM transport.
func NewForCertificate(rw io.ReadWriter, cert *x509.Certificate) (*Key, error) {
	handle, err := FindHandle(rw, cert.PublicKey)
	if err != nil {
		return nil, err
	}
	return New(rw, handle)
}

// OpenForCertificate attaches to the key matching the certificate's public key,
// in the TPM at device. This is usually the call you want: the certificate you
// are about to present picks the key, so nothing needs configuring.
//
//	cert, _ := x509.ParseCertificate(certDER)
//	key, err := tpmtls.OpenForCertificate(tpmtls.DefaultDevice, cert)
func OpenForCertificate(device string, cert *x509.Certificate) (*Key, error) {
	rwc, err := tpm2.OpenTPM(device)
	if err != nil {
		return nil, fmt.Errorf("tpmtls: open %s: %w", device, err)
	}

	key, err := NewForCertificate(rwc, cert)
	if err != nil {
		rwc.Close()
		return nil, err
	}
	key.closer = rwc

	return key, nil
}
