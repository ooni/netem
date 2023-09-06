package netem

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/apex/log"
)

func TestMITMWeCanGenerateAnExpiredCertificate(t *testing.T) {
	topology := Must1(NewStarTopology(log.Log))
	defer topology.Close()

	serverStack := Must1(topology.AddHost("10.0.0.1", "0.0.0.0", &LinkConfig{}))
	clientStack := Must1(topology.AddHost("10.0.0.2", "0.0.0.0", &LinkConfig{}))

	serverAddr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 443}
	serverListener := Must1(serverStack.ListenTCP("tcp", serverAddr))

	serverServer := &http.Server{
		Handler: http.NewServeMux(),
		TLSConfig: &tls.Config{
			GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				// obtain the underlying MITM mechanism and force a long time in the past as
				// the certificate generation time for testing
				config := topology.TLSMITMConfig()
				return config.Config.NewCertWithoutCacheWithTimeNow(
					chi.ServerName,
					func() time.Time {
						return time.Date(2017, time.July, 17, 0, 0, 0, 0, time.UTC)
					},
				)
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
		RootCAs:    Must1(clientStack.TLSMITMConfig().CertPool()),
		ServerName: "www.example.com",
	}
	tlsConn := tls.Client(tcpConn, tlsClientConfig)
	err = tlsConn.HandshakeContext(context.Background())
	if err == nil || !strings.Contains(err.Error(), "x509: certificate has expired or is not yet valid") {
		t.Fatal("unexpected error", err)
	}
}
