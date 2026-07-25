# go-tpm-tls

[![Go Reference](https://pkg.go.dev/badge/github.com/bschaatsbergen/go-tpm-tls.svg)](https://pkg.go.dev/github.com/bschaatsbergen/go-tpm-tls)
[![Go Report Card](https://goreportcard.com/badge/github.com/bschaatsbergen/go-tpm-tls)](https://goreportcard.com/report/github.com/bschaatsbergen/go-tpm-tls)

This project provides a [`crypto.Signer`](https://pkg.go.dev/crypto#Signer)
backed by a key in a TPM, so [`crypto/tls`](https://pkg.go.dev/crypto/tls) can
authenticate a client or server with it. It is a small layer over
[go-tpm](https://github.com/google/go-tpm) and
[go-tpm-tools](https://github.com/google/go-tpm-tools).

It does not create keys. It attaches to one that already exists, usually
provisioned by an attestation agent that generated it inside the TPM and had it
certified.

The key never enters process memory. `crypto/tls` asks a private key to sign the
handshake transcript, the TPM does that internally and returns the signature, so
the process proves possession of a key it never holds. The key also cannot be
copied to another machine.

```go
cert, err := x509.ParseCertificate(certDER)
if err != nil {
	return err
}

key, err := tpmtls.OpenForCertificate(tpmtls.DefaultDevice, cert)
if err != nil {
	return err
}
defer key.Close()

conn, err := tls.Dial("tcp", "store.example.com:443", &tls.Config{
	MinVersion:   tls.VersionTLS13,
	Certificates: []tls.Certificate{key.TLSCertificate(certDER)},
})
```

## Install

```sh
go get github.com/bschaatsbergen/go-tpm-tls
```

The import path is hyphenated, the package is not:

```go
import "github.com/bschaatsbergen/go-tpm-tls" // package tpmtls
```

## Attaching to a key

A `Key` is a key living in a TPM. It implements
[`crypto.Signer`](https://pkg.go.dev/crypto#Signer), so anything that accepts a
private key interface accepts it, and it is safe for concurrent use.

There are four ways in. Two of them differ in how the key is identified, by
handle or by the certificate you are about to present, and two in who owns the
TPM transport.

### `func Open(device string, handle Handle) (*Key, error)`

Opens the TPM at `device` and attaches to the key at `handle`. The returned
`Key` owns the device and closes it on `Close`, so nothing else in the process
holds that descriptor and there is no ordering for the caller to arrange.

`DefaultDevice` is `/dev/tpmrm0`, the Linux resource manager device. Opening it
usually needs root or membership of the `tss` group.

### `func New(rw io.ReadWriter, handle Handle) (*Key, error)`

Attaches over a transport you already have, for when the TPM is shared with
other code in the same process, or in tests against a simulator. The caller
keeps ownership: `Close` releases the key and leaves the transport open.

Sharing puts ordering on the caller. A TPM answers one command at a time, and a
single file descriptor carries one exchange at a time. `Sign` takes a lock, so
concurrent handshakes with one `Key` are safe, but that lock does not cover
commands the caller sends over `rw` directly.

The handle may be persistent or transient. A transient one only resolves over
the transport that created it, so it is useful when the same process both
creates and uses the key, and useless across processes.

### `func OpenForCertificate(device string, cert *x509.Certificate) (*Key, error)`

Attaches to the key matching the certificate's public key. This is usually the
call you want. The handle a key sits at is a provisioning decision, so putting
it in your source couples the application to how one machine was set up, and the
certificate you are about to present already says which key to sign with.

### `func NewForCertificate(rw io.ReadWriter, cert *x509.Certificate) (*Key, error)`

The same, over a transport you already have.

## Using the key

### `func (k *Key) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)`

Asks the TPM to sign `digest`. The digest goes in, a signature comes back, and
the private key stays where it is. This is what `crypto/tls` calls during a
handshake.

Calls are serialized, since a TPM executes one command at a time. A signature
costs milliseconds rather than microseconds, and lands once per full handshake.

### `func (k *Key) Public() crypto.PublicKey`

Returns the public half, read once when the key was loaded.

### `func (k *Key) TLSCertificate(chain ...[]byte) tls.Certificate`

Pairs a certificate chain with this key, ready to put in a
[`tls.Config`](https://pkg.go.dev/crypto/tls#Config). The chain is leaf first
and DER encoded, which is what `crypto/tls` expects.

```go
cfg := &tls.Config{
	Certificates: []tls.Certificate{key.TLSCertificate(leafDER)},
	MinVersion:   tls.VersionTLS13,
}
```

Nothing here is special to TPMs. `crypto/tls` accepts any `crypto.Signer` as a
private key, which is the same door PKCS#11 modules and cloud KMS keys come
through.

### `func (k *Key) CertificateRequest(template *x509.CertificateRequest) ([]byte, error)`

Creates a DER encoded CSR for this key, signed by the TPM. A CSR is how a
certificate authority learns which public key to certify, and its self signature
proves the requester holds the private half. Since the TPM produces that
signature, the proof is as strong as the key.

A `nil` template asks for a certificate with no subject and no SANs, which is
what an issuer that derives those itself expects.

### `func (k *Key) NonExportable() (bool, error)`

Reports whether the TPM will refuse to release or duplicate the private key. It
reads the attributes back from the TPM, so the answer is what the TPM enforces
rather than what the key's creator intended.

### `func (k *Key) Handle() Handle`

Returns the handle the key is loaded at. `Handle` is an alias for
[`tpmutil.Handle`](https://pkg.go.dev/github.com/google/go-tpm/tpmutil#Handle),
so callers need not import go-tpm to name one.

### `func (k *Key) Close() error`

Releases this reference to the key, and closes the device if `Open` opened it.
Safe to call more than once.

The key itself survives. A persistent handle belongs to whoever created it, and
removing one takes an eviction this package does not perform: detaching from a
key you did not provision should not destroy it for everyone else on the
machine.

## Finding a key

### `func FindHandle(rw io.ReadWriter, pub crypto.PublicKey) (Handle, error)`

Returns the handle of the persistent key whose public half is `pub`, or
`ErrNotFound`. This is what `OpenForCertificate` uses, exported for when you
want the handle rather than the key.

### `func PersistentHandles(rw io.ReadWriter) ([]Handle, error)`

Lists the persistent handles present in the TPM, for when you want to see what a
machine holds rather than guess.

## Notes

Use an ECDSA key. RSA keys attach and sign, but not the way `crypto/tls` asks:
TLS wants RSA-PSS at a salt length the TPM will not use, so the handshake fails
at signing time with an error that does not mention any of this.

A TPM signature is slow next to a software key, and it lands once per full
handshake. Where the key sits matters too: a transient object is swapped in and
out around each command, a persistent one is not. Measurements are in
[go-tpm-tls-bench](https://github.com/bschaatsbergen/go-tpm-tls-bench).

## Tests

```sh
go test ./...
```

Tests run against the TPM 2.0 reference simulator, so they need no TPM and no
root. Each one starts by playing the key's owner, creating a key and persisting
it at a handle, then attaches to it through this package, which is the
arrangement the package is written for.

They are small and focused, one behaviour each. They cover attaching, signing
and verification on every curve, concurrent signing, the CSR self signature, a
full mutual TLS handshake against a server that requires and verifies the client
certificate, discovery by public key, and the cases that must fail: a restricted
key, an unknown handle, and RSA.

## License

go-tpm-tls is released under a BSD-style license. See [LICENSE](LICENSE).

## Links

*   [TCG TPM 2.0 Library specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
*   [go-tpm](https://github.com/google/go-tpm) and [go-tpm-tools](https://github.com/google/go-tpm-tools)
*   [RFC 8446, TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446), for what `CertificateVerify` signs
