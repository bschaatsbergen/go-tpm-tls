// Copyright 2026 Bruno Schaatsbergen. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmtls_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/bschaatsbergen/go-tpm-tls"
)

// Authenticate to a server with a key the TPM will never release.
//
// The certificate picks the key, so there is nothing to configure: whatever the
// agent provisioned, the public key in the certificate finds it.
func Example() {
	certPEM, err := os.ReadFile("client.crt")
	if err != nil {
		log.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	key, err := tpmtls.OpenForCertificate(tpmtls.DefaultDevice, cert)
	if err != nil {
		log.Fatal(err)
	}
	defer key.Close()

	conn, err := tls.Dial("tcp", "store.example.com:443", &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{key.TLSCertificate(block.Bytes)},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
}

// Attach to a key by handle, for deployments that provision a known one.
//
// The handle comes from configuration rather than a constant in the source. Two
// machines provisioned by different tooling can hold their keys at different
// handles, and a literal here would quietly work on one and fail on the other.
func ExampleOpen() {
	raw := os.Getenv("TPM_KEY_HANDLE") // for example 0x81000004
	handle, err := strconv.ParseUint(raw, 0, 32)
	if err != nil {
		log.Fatalf("TPM_KEY_HANDLE: %v", err)
	}

	key, err := tpmtls.Open(tpmtls.DefaultDevice, tpmtls.Handle(handle))
	if err != nil {
		log.Fatal(err)
	}
	defer key.Close()

	fmt.Printf("signing with the key at %#x\n", key.Handle())
}

// Ask an issuer to certify the key.
//
// The request carries the public half, and the signature over it, made by the
// TPM, is what proves this machine holds the private half.
func ExampleKey_CertificateRequest() {
	key, err := tpmtls.Open(tpmtls.DefaultDevice, 0x81000004)
	if err != nil {
		log.Fatal(err)
	}
	defer key.Close()

	csr, err := key.CertificateRequest(&x509.CertificateRequest{})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%d byte certificate request\n", len(csr))
}
