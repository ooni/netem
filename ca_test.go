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
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/apex/log"
	"github.com/google/go-cmp/cmp"
)

func TestCAMustNewTLSCertificate(t *testing.T) {
	ca := MustNewCA()

	tlsc := ca.MustNewTLSCertificate("example.com", "www.example.com", "10.0.0.1", "10.0.0.2")

	if tlsc.Certificate == nil {
		t.Error("tlsc.Certificate: got nil, want certificate bytes")
	}
	if tlsc.PrivateKey == nil {
		t.Error("tlsc.PrivateKey: got nil, want private key")
	}

	x509c := tlsc.Leaf
	if x509c == nil {
		t.Fatal("x509c: got nil, want *x509.Certificate")
	}

	if got := x509c.SerialNumber; got.Cmp(caMaxSerialNumber) >= 0 {
		t.Errorf("x509c.SerialNumber: got %v, want <= MaxSerialNumber", got)
	}
	if got, want := x509c.Subject.CommonName, "example.com"; got != want {
		t.Errorf("X509c.Subject.CommonName: got %q, want %q", got, want)
	}
	if err := x509c.VerifyHostname("example.com"); err != nil {
		t.Errorf("x509c.VerifyHostname(%q): got %v, want no error", "example.com", err)
	}

	if got, want := x509c.Subject.Organization, []string{"OONI Netem CA"}; !reflect.DeepEqual(got, want) {
		t.Errorf("x509c.Subject.Organization: got %v, want %v", got, want)
	}

	if got := x509c.SubjectKeyId; got == nil {
		t.Error("x509c.SubjectKeyId: got nothing, want key ID")
	}
	if !x509c.BasicConstraintsValid {
		t.Error("x509c.BasicConstraintsValid: got false, want true")
	}

	if got, want := x509c.KeyUsage, x509.KeyUsageKeyEncipherment; got&want == 0 {
		t.Error("x509c.KeyUsage: got nothing, want to include x509.KeyUsageKeyEncipherment")
	}
	if got, want := x509c.KeyUsage, x509.KeyUsageDigitalSignature; got&want == 0 {
		t.Error("x509c.KeyUsage: got nothing, want to include x509.KeyUsageDigitalSignature")
	}

	want := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if got := x509c.ExtKeyUsage; !reflect.DeepEqual(got, want) {
		t.Errorf("x509c.ExtKeyUsage: got %v, want %v", got, want)
	}

	if got, want := x509c.DNSNames, []string{"example.com", "www.example.com"}; !reflect.DeepEqual(got, want) {
		t.Errorf("x509c.DNSNames: got %v, want %v", got, want)
	}

	if diff := cmp.Diff(x509c.IPAddresses, []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")}); diff != "" {
		t.Errorf(diff)
	}

	before := time.Now().Add(-2 * time.Hour)
	if got := x509c.NotBefore; before.After(got) {
		t.Errorf("x509c.NotBefore: got %v, want after %v", got, before)
	}

	after := time.Now().Add(2 * time.Hour)
	if got := x509c.NotAfter; !after.After(got) {
		t.Errorf("x509c.NotAfter: got %v, want before %v", got, want)
	}
}

func TestCAWeCanGenerateAnExpiredCertificate(t *testing.T) {
	topology := MustNewStarTopology(log.Log)
	defer topology.Close()

	serverStack := Must1(topology.AddHost("10.0.0.1", "0.0.0.0", &LinkConfig{}))
	clientStack := Must1(topology.AddHost("10.0.0.2", "0.0.0.0", &LinkConfig{}))

	serverAddr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 443}
	serverListener := Must1(serverStack.ListenTCP("tcp", serverAddr))

	serverServer := &http.Server{
		Handler: http.NewServeMux(),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{
				*serverStack.MustNewTLSCertificateWithTimeNow(func() time.Time {
					return time.Date(2017, time.July, 17, 0, 0, 0, 0, time.UTC)
				},
					"www.example.com",
					"10.0.0.1",
				),
			},
		},
	}
	go serverServer.ServeTLS(serverListener, "", "")
	defer serverServer.Close()

	tcpConn, err := clientStack.DialContext(context.Background(), "tcp", "10.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpConn.Close()

	tlsClientConfig := &tls.Config{
		RootCAs:    clientStack.DefaultCertPool(),
		ServerName: "www.example.com",
	}
	tlsConn := tls.Client(tcpConn, tlsClientConfig)
	err = tlsConn.HandshakeContext(context.Background())
	if err == nil || !strings.Contains(err.Error(), "x509: certificate has expired or is not yet valid") {
		t.Fatal("unexpected error", err)
	}
}
