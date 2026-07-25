// Copyright 2026 Bruno Schaatsbergen. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmtls

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

// TLSCertificate pairs a certificate chain with this key, ready to drop into a
// tls.Config. The chain is leaf first and DER encoded, which is what crypto/tls
// expects.
//
//	cfg := &tls.Config{
//		Certificates: []tls.Certificate{key.TLSCertificate(leafDER)},
//		MinVersion:   tls.VersionTLS13,
//	}
//
// Nothing here is special to TPMs. crypto/tls accepts any crypto.Signer as a
// private key, which is the same door PKCS#11 modules and cloud KMS keys come
// through.
func (k *Key) TLSCertificate(chain ...[]byte) tls.Certificate {
	return tls.Certificate{
		Certificate: chain,
		PrivateKey:  k,
		// Leaf is left nil on purpose. crypto/tls parses it when it needs to,
		// and filling it in here would mean parsing the DER and swallowing an
		// error this signature has no way to report.
		Leaf: nil,
	}
}

// CertificateRequest creates a DER encoded CSR for this key, signed by the TPM.
//
// A CSR is how a certificate authority learns which public key to certify, and
// its self signature is what proves the requester holds the private half. Since
// the TPM produces that signature, the proof is as strong as the key: it can
// only have come from this machine.
//
// A nil template asks for a certificate with no subject and no SANs, which is
// what an issuer that derives those itself expects. SPIRE is one such issuer: it
// names the workload from attestation and reads only the public key out of the
// request.
func (k *Key) CertificateRequest(template *x509.CertificateRequest) ([]byte, error) {
	if template == nil {
		template = &x509.CertificateRequest{}
	}

	// Software signers take their signature nonce from this reader. The TPM has
	// its own entropy and ignores it, but crypto/x509 wants one regardless.
	der, err := x509.CreateCertificateRequest(rand.Reader, template, k)
	if err != nil {
		return nil, fmt.Errorf("tpmtls: create certificate request: %w", err)
	}

	return der, nil
}
