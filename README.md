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

Use `OpenForCertificate` and pass the certificate you plan to present. It opens
the TPM and picks the key whose public half matches, so you do not have to
configure a handle that differs from machine to machine. Use `Open` when you do
know the handle. Both close the device when you close the key.

`New` and `NewForCertificate` are the same two over a TPM connection you already
have, and they leave it open. Use them when the TPM is shared with other code in
the same process, or in tests against a simulator.

The full API — signing, CSRs, finding handles — is documented at
[pkg.go.dev](https://pkg.go.dev/github.com/bschaatsbergen/go-tpm-tls).

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
