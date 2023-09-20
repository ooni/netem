// Copyright 2015 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package netem

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"
)

// caMaxSerialNumber is the upper boundary that is used to create unique serial
// numbers for the certificate. This can be any unsigned integer up to 20
// bytes (2^(8*20)-1).
var caMaxSerialNumber = big.NewInt(0).SetBytes(bytes.Repeat([]byte{255}, 20))

// caMustNewAuthority creates a new CA certificate and associated private key or PANICS.
//
// This code is derived from github.com/google/martian/v3.
//
// SPDX-License-Identifier: Apache-2.0.
func caMustNewAuthority(name, organization string, validity time.Duration,
	timeNow func() time.Time) (*x509.Certificate, *rsa.PrivateKey) {
	priv := Must1(rsa.GenerateKey(rand.Reader, 2048))
	pub := priv.Public()

	// Subject Key Identifier support for end entity certificate.
	// https://www.ietf.org/rfc/rfc3280.txt (section 4.2.1.2)
	pkixpub := Must1(x509.MarshalPKIXPublicKey(pub))
	h := sha1.New()
	h.Write(pkixpub)
	keyID := h.Sum(nil)

	// TODO(bassosimone): keep a map of used serial numbers to avoid potentially
	// reusing a serial multiple times.
	serial := Must1(rand.Int(rand.Reader, caMaxSerialNumber))

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{organization},
		},
		SubjectKeyId:          keyID,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		NotBefore:             timeNow().Add(-validity),
		NotAfter:              timeNow().Add(validity),
		DNSNames:              []string{name},
		IsCA:                  true,
	}

	raw := Must1(x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv))

	// Parse certificate bytes so that we have a leaf certificate.
	x509c := Must1(x509.ParseCertificate(raw))

	return x509c, priv
}

// CA is a certification authority.
//
// The zero value is invalid, please use [NewCA] to construct.
//
// This code is derived from github.com/google/martian/v3.
//
// SPDX-License-Identifier: Apache-2.0.
type CA struct {
	caCert   *x509.Certificate
	capriv   any
	keyID    []byte
	org      string
	priv     *rsa.PrivateKey
	validity time.Duration
}

// NewCA creates a new certification authority.
func MustNewCA() *CA {
	return MustNewCAWithTimeNow(time.Now)
}

var _ CertificationAuthority = &CA{}

// MustNewCA is like [NewCA] but uses a custom [time.Now] func.
//
// This code is derived from github.com/google/martian/v3.
//
// SPDX-License-Identifier: Apache-2.0.
func MustNewCAWithTimeNow(timeNow func() time.Time) *CA {
	ca, privateKey := caMustNewAuthority("jafar", "OONI", 24*time.Hour, timeNow)

	roots := x509.NewCertPool()
	roots.AddCert(ca)

	priv := Must1(rsa.GenerateKey(rand.Reader, 2048))
	pub := priv.Public()

	// Subject Key Identifier support for end entity certificate.
	// https://www.ietf.org/rfc/rfc3280.txt (section 4.2.1.2)
	pkixpub := Must1(x509.MarshalPKIXPublicKey(pub))
	h := sha1.New()
	h.Write(pkixpub)
	keyID := h.Sum(nil)

	return &CA{
		caCert:   ca,
		capriv:   privateKey,
		priv:     priv,
		keyID:    keyID,
		validity: time.Hour,
		org:      "OONI Netem CA",
	}
}

// CACert implements [CertificationAuthority].
func (ca *CA) CACert() *x509.Certificate {
	return ca.caCert
}

// DefaultCertPool implements [CertificationAuthority].
func (ca *CA) DefaultCertPool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.caCert)
	return p
}

// MustNewServerTLSConfig implements [CertificationAuthority].
func (ca *CA) MustNewServerTLSConfig(commonName string, extraNames ...string) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{*ca.MustNewTLSCertificate(commonName, extraNames...)},
	}
}

// MustNewTLSCertificate implements [CertificationAuthority].
func (ca *CA) MustNewTLSCertificate(commonName string, extraNames ...string) *tls.Certificate {
	return ca.MustNewTLSCertificateWithTimeNow(time.Now, commonName, extraNames...)
}

// MustNewCertWithTimeNow is like [MustNewCert] but uses a custom [time.Now] func.
//
// This code is derived from github.com/google/martian/v3.
//
// SPDX-License-Identifier: Apache-2.0.
func (ca *CA) MustNewTLSCertificateWithTimeNow(timeNow func() time.Time,
	commonName string, extraNames ...string) *tls.Certificate {
	serial := Must1(rand.Int(rand.Reader, caMaxSerialNumber))

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{ca.org},
		},
		SubjectKeyId:          ca.keyID,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		NotBefore:             timeNow().Add(-ca.validity),
		NotAfter:              timeNow().Add(ca.validity),
	}

	allNames := []string{commonName}
	allNames = append(allNames, extraNames...)
	for _, name := range allNames {
		if ip := net.ParseIP(name); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, name)
		}
	}

	raw := Must1(x509.CreateCertificate(rand.Reader, tmpl, ca.caCert, ca.priv.Public(), ca.capriv))

	// Parse certificate bytes so that we have a leaf certificate.
	x509c := Must1(x509.ParseCertificate(raw))

	tlsc := &tls.Certificate{
		Certificate: [][]byte{raw, ca.caCert.Raw},
		PrivateKey:  ca.priv,
		Leaf:        x509c,
	}

	return tlsc
}
