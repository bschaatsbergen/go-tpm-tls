# go-tpm-tls

[![Go Reference](https://pkg.go.dev/badge/github.com/bschaatsbergen/go-tpm-tls.svg)](https://pkg.go.dev/github.com/bschaatsbergen/go-tpm-tls)
[![CI](https://github.com/bschaatsbergen/go-tpm-tls/actions/workflows/ci.yml/badge.svg)](https://github.com/bschaatsbergen/go-tpm-tls/actions/workflows/ci.yml)

This project provides a [`crypto.Signer`](https://pkg.go.dev/crypto#Signer)
backed by a key in a TPM, so [`crypto/tls`](https://pkg.go.dev/crypto/tls) can
authenticate a client or server with a key that never leaves the TPM. It is a
small layer over
[go-tpm](https://github.com/google/go-tpm) and
[go-tpm-tools](https://github.com/google/go-tpm-tools).

It does not create keys. It attaches to one that already exists, usually
provisioned by an attestation agent that generated it inside the TPM and had it
certified.

`crypto/tls` asks a private key to sign the handshake transcript. The TPM does
that internally and returns the signature, so the key is used without ever being
read out, and there is nothing in process memory to leak or copy elsewhere.

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

A TPM signature costs milliseconds where a software key costs microseconds, and
it lands once per full handshake rather than once per request. Session resumption
and connection reuse keep it off later connections, which is usually enough to
make it irrelevant.

Signing is serialized, since a TPM runs one command at a time, so what a machine
is limited to is new handshakes per second, not requests per second. That limit
is per machine, since each machine has its own TPM.

Where the key sits matters as much as any of this. A transient object is swapped
in and out by the kernel resource manager around each command, so every signature
pays to load the key back in, roughly ten times the cost of a persistent one.
Measurements are in
[go-tpm-tls-bench](https://github.com/bschaatsbergen/go-tpm-tls-bench).

## Tests

```sh
go test ./...
golangci-lint run
```

Tests run against the TPM 2.0 reference simulator, so they need no TPM and no
root.

## License

go-tpm-tls is released under a BSD-style license. See [LICENSE](LICENSE).

## Links

*   [TCG TPM 2.0 Library specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
*   [go-tpm](https://github.com/google/go-tpm) and [go-tpm-tools](https://github.com/google/go-tpm-tools)
*   [RFC 8446, TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446), for what `CertificateVerify` signs
