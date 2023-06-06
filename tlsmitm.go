package netem

//
// TLS: MITM configuration
//

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"time"

	"github.com/google/martian/v3/mitm"
)

// TLSMITMConfig contains configuration for TLS MITM operations. You MUST use the
// [NewMITMConfig] factory to create a new instance. You will need to pass this
// instance to [NewGVisorStack] so that all the [GvisorStack] can communicate with
// each other using the same underlying (fake) root CA pool.
type TLSMITMConfig struct {
	// cert is the fake CA certificate for MITM.
	cert *x509.Certificate

	// config is the MITM config to generate certificates on the fly.
	config *mitm.Config

	// key is the private key that signed the mitmCert.
	key *rsa.PrivateKey
}

// NewTLSMITMConfig creates a new [MITMConfig].
func NewTLSMITMConfig() (*TLSMITMConfig, error) {
	cert, key, err := mitm.NewAuthority("jafar", "OONI", 24*time.Hour)
	if err != nil {
		return nil, err
	}
	config, err := mitm.NewConfig(cert, key)
	if err != nil {
		return nil, err
	}
	mitmConfig := &TLSMITMConfig{
		cert:   cert,
		config: config,
		key:    key,
	}
	return mitmConfig, nil
}

// CertPool returns an [x509.CertPool] using the given [MITMConfig].
func (c *TLSMITMConfig) CertPool() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	pool.AddCert(c.cert)
	return pool, nil
}

// TLSConfig returns a *tls.Config that will generate certificates on-the-fly using
// the SNI extension in the TLS ClientHello, or the remote server's IP as a fallback SNI.
func (c *TLSMITMConfig) TLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: false,
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			martianConfig := c.config.TLSForHost(tlsAddrFromClientHello(clientHello))
			return martianConfig.GetCertificate(clientHello)
		},
		NextProtos: []string{"http/1.1"},
	}
}

// tlsAddrFromClientHello extracts the server addr from the ClientHelloInfo struct. This fixes
// cases where we have a fake server listening on, say, 8.8.8.8, and the client attempts to
// connect to the https://8.8.8.8/ URL without using any SNI.
func tlsAddrFromClientHello(clientHello *tls.ClientHelloInfo) string {
	addr := clientHello.Conn.LocalAddr()
	if addr == nil {
		return ""
	}
	return addr.String()
}
