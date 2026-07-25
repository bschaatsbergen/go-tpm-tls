# go-tpm-tls

Turns a key that already lives in a TPM into a `crypto.Signer`, so it can be
used as the private key of a TLS certificate.

The package does not create keys. Something else owns them: typically an
attestation agent that generated a key inside the TPM, bound its public half
into hardware evidence, and had it certified. That key sits at a persistent
handle, and this package attaches to it.

What you get is proof of possession without possession. `crypto/tls` only ever
asks a private key to sign a digest, the TPM does that internally, and the key
never enters process memory. A heap dump, a core file, or a swapped page has
nothing to leak, and the key cannot be copied to another machine at all. An
attacker who compromises the process can use the key while they have access, but
they cannot take it with them.

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

## API

| | |
| --- | --- |
| `OpenForCertificate(device, cert)` | attach to the key matching a certificate |
| `NewForCertificate(rw, cert)` | the same, over an open transport |
| `Open(device, handle)` | attach to a key by handle |
| `New(rw, handle)` | the same, over an open transport |
| `FindHandle(rw, pub)` | handle of the key with this public half |
| `PersistentHandles(rw)` | persistent handles present in the TPM |
| `Key.Public()` | public half |
| `Key.Sign(rand, digest, opts)` | signature from the TPM, serialized |
| `Key.TLSCertificate(chain...)` | a `tls.Certificate` using this key |
| `Key.CertificateRequest(template)` | DER CSR, signed by the TPM |
| `Key.NonExportable()` | key attributes read back from the TPM |
| `Key.Handle()` | the handle the key is loaded at |
| `Key.Close()` | detach, and close the device if `Open` opened it |

`Open` and `New` differ in who owns the TPM transport.

`Open` opens the device itself and closes it on `Close`. Nothing else in the
process holds that descriptor, so every command sent over it goes through this
package's lock. Use it when this is the only code in your process talking to the
TPM.

`New` takes a transport you already have and does not close it. Whoever opened
the descriptor closes it, since closing one that another part of the program is
still using breaks that code with an error pointing nowhere near here.

Sharing a transport puts ordering on the caller. A TPM answers one command at a
time, and a single file descriptor carries one exchange at a time. The kernel
resource manager gives each open descriptor its own context, so separate
descriptors do not interfere, but two goroutines writing to the same descriptor
will interleave. `Sign` takes a lock, so concurrent handshakes with one `Key` are
safe. That lock does not cover commands the caller sends over `rw` directly, so
serialize those yourself.

`Close` detaches. It does not evict the key, which belongs to whoever created it:
a workload finishing its work should not take the machine's identity with it.

A `Key` is safe for concurrent use. Signing is serialized behind a mutex, since
the TPM executes one command at a time and TLS servers handshake in parallel.

The key has to be an unrestricted signing key. TLS 1.3 client authentication
signs a digest chosen by the peer, and a restricted TPM key, an attestation key
for instance, refuses to do that. Attaching to one fails immediately rather than
at the first handshake.

## Which key

A persistent handle is a number between 0x81000000 and 0x81FFFFFF, chosen by
whoever created the key. TCG reserves parts of the range by convention:
0x81000001 is usually the storage root key, and 0x81010001 and 0x81010002 the RSA
and ECC endorsement keys. An agent provisioning a signing key picks something
clear of those, such as 0x81000004. Once persisted, the handle survives reboots
until something evicts the key.

Which number a machine ended up with is a provisioning decision, so putting it in
your source couples the application to how one machine happened to be set up. Two
machines provisioned by different tooling can differ, and a literal would work on
one and fail on the other.

`OpenForCertificate` sidesteps this. The application already holds the
certificate it is about to present, and the public key in it says exactly which
key in the TPM to sign with. `PersistentHandles` and `FindHandle` are there when
you want to look yourself, and `Open` takes a handle directly for deployments
where it genuinely is known configuration.

## Notes

Opening `/dev/tpmrm0` usually needs root or membership of the `tss` group. It is
the resource manager device, which multiplexes access, so prefer it over
`/dev/tpm0` when other processes use the TPM too.

A TPM signature is slow next to a software key, around 21 ms on a Google Cloud
Confidential VM, and it lands once per full handshake. Session resumption and
connection reuse take it out of the path after the first connection.
Measurements are in
[vtpm-tls-bench](https://github.com/bschaatsbergen/vtpm-tls-bench).

## Tests

```sh
go test ./...
```

Tests run against the TPM 2.0 reference simulator, so they need no TPM and no
root. Each one starts by playing the key's owner, creating a key and persisting
it at a handle, then attaches to it through this package, which is the
arrangement the package is written for.

They cover attaching, signing and verification, concurrent signing, the CSR self
signature, a full mutual TLS handshake against a server that requires and
verifies the client certificate, that the TPM reports the key as non-exportable,
that an unknown handle fails, and that `Close` leaves the key where it found it.
