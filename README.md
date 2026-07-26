# go-tpm-tls

[![Go Reference](https://pkg.go.dev/badge/github.com/bschaatsbergen/go-tpm-tls.svg)](https://pkg.go.dev/github.com/bschaatsbergen/go-tpm-tls)

Provides a [`crypto.Signer`](https://pkg.go.dev/crypto#Signer)
backed by a key in a TPM, so [`crypto/tls`](https://pkg.go.dev/crypto/tls) can
authenticate a client or server with a key that never leaves the TPM. It is a
small layer over
[go-tpm](https://github.com/google/go-tpm) and
[go-tpm-tools](https://github.com/google/go-tpm-tools).

It does not create keys. It attaches to one that already exists, usually
provisioned by an attestation agent that generated it inside the TPM and had it
certified.

`crypto/tls` asks a private key to sign the handshake transcript. The TPM signs
internally and hands back the signature. The key is never read out, so there is
nothing in process memory to leak.

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

A `Key` is a key in a TPM. It implements
[`crypto.Signer`](https://pkg.go.dev/crypto#Signer), so it goes straight into a
[`tls.Config`](https://pkg.go.dev/crypto/tls#Config) as a private key, and it is
safe for concurrent use.

Use `OpenForCertificate` and pass the certificate you plan to present. It opens
the TPM and picks the key whose public half matches, so you do not have to
configure a handle that differs from machine to machine.

Use `Open` when you do know the handle. Both close the device when you close the
key.

`New` and `NewForCertificate` are the same two over a TPM connection you already
have, and they leave it open.

### `func Open(device string, handle Handle) (*Key, error)`

Opens the TPM at `device` and attaches to the key at `handle`. The `Key` owns
the device and closes it with `Close`.

`DefaultDevice` is `/dev/tpmrm0`, the Linux resource manager device. Opening it
usually needs root or membership of the `tss` group.

### `func New(rw io.ReadWriter, handle Handle) (*Key, error)`

Attaches over a transport you already have. The caller keeps ownership, so
`Close` releases the key and leaves the transport open. Use it when the TPM is
shared with other code in the same process, or in tests against a simulator.

Sharing puts ordering on you. A TPM runs one command at a time and a file
descriptor carries one exchange at a time. `Sign` locks, so concurrent handshakes
with one `Key` are safe, but the lock does not cover commands you send over `rw`
yourself.

The handle can be persistent or transient. Transient handles only resolve on the
transport that created them, so they are no use across processes.

### `func OpenForCertificate(device string, cert *x509.Certificate) (*Key, error)`

Attaches to the key matching the certificate's public key. Usually the call you
want, since it saves configuring a handle that differs from machine to machine.

### `func NewForCertificate(rw io.ReadWriter, cert *x509.Certificate) (*Key, error)`

The same, over a transport you already have.

## Using the key

### `func (k *Key) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)`

Asks the TPM to sign `digest`. This is what `crypto/tls` calls during a
handshake.

Calls are serialized, since a TPM runs one command at a time. Expect
milliseconds, once per full handshake.

### `func (k *Key) Public() crypto.PublicKey`

Returns the public half.

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

Nothing here is TPM specific. `crypto/tls` takes any `crypto.Signer` as a private
key, the same as a PKCS#11 module or a cloud KMS.

### `func (k *Key) CertificateRequest(template *x509.CertificateRequest) ([]byte, error)`

Creates a DER encoded CSR, signed by the TPM. The self signature is what proves
to the issuer that this machine holds the private half.

Pass `nil` for a request with no subject and no SANs, which is what an issuer
that derives those itself expects.

### `func (k *Key) NonExportable() (bool, error)`

Reports whether the TPM will refuse to release or duplicate the key. Read from
the TPM itself, not from the template the key was created with.

### `func (k *Key) Handle() Handle`

Returns the handle the key is loaded at. `Handle` is an alias for
[`tpmutil.Handle`](https://pkg.go.dev/github.com/google/go-tpm/tpmutil#Handle),
so you do not need to import go-tpm to name one.

### `func (k *Key) Close() error`

Releases the key, and closes the device if `Open` opened it. Safe to call twice.

The key itself stays put. Removing a persistent key takes an eviction, which this
package never does: detaching from a key you did not provision should not destroy
it for everything else on the machine.

## Finding a key

### `func FindHandle(rw io.ReadWriter, pub crypto.PublicKey) (Handle, error)`

Returns the handle of the persistent key whose public half is `pub`, or
`ErrNotFound`. What `OpenForCertificate` uses, exported for when you want the
handle and not the key.

### `func PersistentHandles(rw io.ReadWriter) ([]Handle, error)`

Lists the persistent handles in the TPM.

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
