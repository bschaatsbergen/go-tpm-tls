// Copyright 2026 Bruno Schaatsbergen. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tpmtls turns a key that already lives in a TPM into a crypto.Signer,
// so it can be used as the private key of a TLS certificate.
//
// The package deliberately does not create keys. Something else owns them:
// typically an attestation agent that generated a key inside the TPM, bound its
// public half into hardware evidence, and had it certified. This package
// attaches to whatever that left behind.
//
// Usually the key sits at a persistent handle, which survives reboots and is
// reachable by whichever process comes along later. A transient handle works
// just as well while the object is loaded, but only over the transport it was
// created on, since the kernel resource manager keeps transient handles private
// to the connection that made them.
//
// What you get is proof of possession without possession: crypto/tls only ever
// asks a private key to sign a digest, the TPM does that internally, and the key
// never enters process memory. A heap dump, a core file, or a swapped page has
// nothing to leak, and the key cannot be copied to another machine at all. An
// attacker who compromises the process can use the key for as long as they have
// access, but they cannot take it with them.
//
//	key, err := tpmtls.Open(tpmtls.DefaultDevice, 0x81000004)
//	if err != nil {
//		return err
//	}
//	defer key.Close()
//
//	cfg := &tls.Config{
//		Certificates: []tls.Certificate{key.TLSCertificate(certDER)},
//		MinVersion:   tls.VersionTLS13,
//	}
//
// Concurrency: a Key is safe for concurrent use. Signing is serialized, since a
// TPM processes one command at a time and TLS servers handshake in parallel.
package tpmtls

import (
	"crypto"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// DefaultDevice is the TPM resource manager device on Linux. Prefer it over
// /dev/tpm0: the kernel resource manager multiplexes access, so several
// processes can talk to the TPM without fighting over its handle slots.
// Opening it usually needs root or membership of the tss group.
const DefaultDevice = "/dev/tpmrm0"

// Handle is where a key sits in the TPM. Persistent handles run from 0x81000000
// to 0x81FFFFFF, and which one a key uses is decided by whoever created it.
//
// This is an alias rather than a defined type so callers can pass handles they
// already have from go-tpm without converting, and can name one here without
// importing tpmutil themselves.
type Handle = tpmutil.Handle

// Key is a key living in a TPM, exposed as a crypto.Signer so it can be used as
// the PrivateKey of a tls.Certificate.
//
// Concurrency: safe for concurrent use, see the note on Sign.
type Key struct {
	// mu serializes TPM commands. The TPM itself handles one at a time, so
	// without this two goroutines handshaking at once would interleave commands
	// on the same transport.
	mu sync.Mutex

	// key is the loaded key as go-tpm-tools models it. We keep it for its handle
	// and to release our reference on Close.
	key *client.Key

	// signer is the crypto.Signer go-tpm-tools builds over the key. Sign
	// forwards to it under mu.
	signer crypto.Signer

	// rw is the TPM transport. Needed after construction for ReadPublic, and
	// held rather than re-derived because the caller may own it.
	rw io.ReadWriter

	// closer is set only when Open created the transport, in which case Close
	// closes it. It stays nil when the caller passed one to New, since we do not
	// close what we did not open.
	closer io.Closer

	// closed guards against use after Close. Signing on a released key would
	// fail somewhere inside the TPM stack with a confusing error, so we return a
	// clear one instead.
	closed bool
}

// Open attaches to the key at handle in the TPM at device.
//
// The returned Key owns the device and closes it on Close. Nothing else in the
// process holds that descriptor, so every command sent over it goes through this
// package's lock and the caller has no ordering to arrange. Use this unless you
// already have a transport.
func Open(device string, handle Handle) (*Key, error) {
	rwc, err := tpm2.OpenTPM(device)
	if err != nil {
		return nil, fmt.Errorf("tpmtls: open %s: %w", device, err)
	}

	key, err := New(rwc, handle)
	if err != nil {
		// New failed, so nobody else holds the transport we just opened.
		// Nothing to do with a close error here.
		_ = rwc.Close()
		return nil, err
	}
	key.closer = rwc

	return key, nil
}

// New attaches to the key at handle over an already open TPM transport, for when
// the TPM is shared with other code in the same process, or in tests against a
// simulator.
//
// The handle may be persistent or transient. A transient one only resolves over
// the transport it was created on, so it is useful when the same process both
// creates and uses the key, and useless across processes.
//
// The caller keeps ownership of rw. Close releases the reference to the key and
// leaves the transport open: whoever opened the descriptor closes it, since
// closing one that another part of the program is still using breaks that code
// with an error pointing nowhere near here.
//
// Sharing a transport puts ordering on the caller. A TPM answers one command at
// a time, and a single file descriptor carries one exchange at a time. The
// kernel resource manager gives each open descriptor its own context, so
// separate descriptors do not interfere, but two goroutines writing to the same
// descriptor will interleave. Sign takes a lock, so concurrent handshakes with
// this Key are safe. That lock does not cover commands the caller sends over rw
// directly.
func New(rw io.ReadWriter, handle Handle) (*Key, error) {
	// LoadCachedKey reads the public area at the handle and fails if nothing is
	// there. It will not create anything, which is the point: the key belongs to
	// whoever provisioned it.
	//
	// The nil session means "work it out from the key's auth policy", which
	// lands on a null session for the unrestricted signing keys this package is
	// for.
	k, err := client.LoadCachedKey(rw, handle, nil)
	if err != nil {
		return nil, fmt.Errorf("tpmtls: load key at %#x: %w", handle, err)
	}

	// Fail here rather than at the first handshake. A restricted key, an
	// attestation key for instance, refuses to sign a caller supplied digest,
	// and TLS CertificateVerify is exactly that.
	signer, err := k.GetSigner()
	if err != nil {
		k.Close()
		return nil, fmt.Errorf("tpmtls: key at %#x cannot sign: %w", handle, err)
	}

	return &Key{key: k, signer: signer, rw: rw}, nil
}

// Public returns the public half of the key.
//
// No lock is taken: the public area was read once at load time and does not
// change while the key is loaded.
func (k *Key) Public() crypto.PublicKey {
	return k.signer.Public()
}

// Sign asks the TPM to sign digest, which is what makes this type useful to
// crypto/tls. The digest goes in, a signature comes back, and the private key
// stays where it is.
//
// Calls are serialized. A TPM executes one command at a time, so parallel
// signing would either interleave on the transport or queue in the kernel
// anyway. Expect roughly 20ms per signature on a cloud vTPM, paid once per full
// TLS handshake. Session resumption and connection reuse avoid it on subsequent
// connections.
func (k *Key) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.closed {
		return nil, errors.New("tpmtls: key is closed")
	}

	return k.signer.Sign(rand, digest, opts)
}

// NonExportable reports whether the TPM will refuse to release or duplicate the
// private key.
//
// It reads the attributes back from the TPM rather than trusting how the key was
// requested, so the answer is what the TPM enforces, not what its creator
// intended. Worth checking when you inherit a key and want to know what you have.
func (k *Key) NonExportable() (bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.closed {
		return false, errors.New("tpmtls: key is closed")
	}

	pub, _, _, err := tpm2.ReadPublic(k.rw, k.key.Handle())
	if err != nil {
		return false, fmt.Errorf("tpmtls: read public: %w", err)
	}

	// FixedTPM means the private key cannot be duplicated to another TPM. Paired
	// with SensitiveDataOrigin at creation, which says the TPM generated it
	// rather than importing it, the key has never existed anywhere else.
	return pub.Attributes&tpm2.FlagFixedTPM != 0, nil
}

// Handle returns the handle the key is loaded at.
func (k *Key) Handle() Handle {
	return k.key.Handle()
}

// Close releases this reference to the key, and closes the device if Open opened
// it. It is safe to call more than once.
//
// The key itself survives. A persistent handle belongs to whoever created it,
// and removing one takes an eviction this package deliberately does not perform:
// detaching from a key you did not provision should not destroy it for everyone
// else on the machine.
func (k *Key) Close() error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.closed {
		return nil
	}
	k.closed = true

	// This flushes transient handles. For a persistent handle the TPM rejects
	// the flush and nothing happens, which is the behaviour we rely on here.
	k.key.Close()

	if k.closer != nil {
		return k.closer.Close()
	}

	return nil
}
