package netem

//
// Stdlib-based implementation of [UnderlyingNetwork]
//

import (
	"context"
	"crypto/x509"
	"net"
)

// Stdlib implements [UnderlyingNetwork] using the Go stdlib. The zero
// value of this structure is ready to use.
type Stdlib struct {
	// Dialer is the OPTIONAL [net.Dialer] to use.
	Dialer *net.Dialer

	// Resolver is the OPTIONAL [net.Resolver] to use.
	Resolver *net.Resolver
}

var _ UnderlyingNetwork = &Stdlib{}

// DefaultCertPool implements UnderlyingNetwork
func (s *Stdlib) DefaultCertPool() (*x509.CertPool, error) {
	return x509.SystemCertPool()
}

// DialContext implements UnderlyingNetwork
func (s *Stdlib) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	// Implementation note: reject domain names like our Gvisor
	// based counterpart does, so we are consistent.
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if net.ParseIP(host) == nil {
		return nil, ErrNotIPAddress
	}
	return s.dialer().DialContext(ctx, network, address)
}

// GetaddrinfoLookupANY implements UnderlyingNetwork
func (s *Stdlib) GetaddrinfoLookupANY(ctx context.Context, domain string) ([]string, string, error) {
	addrs, err := s.resolver().LookupHost(ctx, domain)
	return addrs, "", err
}

// GetaddrinfoResolverNetwork implements UnderlyingNetwork
func (s *Stdlib) GetaddrinfoResolverNetwork() string {
	return "unknown"
}

// ListenTCP implements UnderlyingNetwork
func (s *Stdlib) ListenTCP(network string, addr *net.TCPAddr) (net.Listener, error) {
	return net.ListenTCP(network, addr)
}

// ListenUDP implements UnderlyingNetwork
func (s *Stdlib) ListenUDP(network string, addr *net.UDPAddr) (UDPLikeConn, error) {
	return net.ListenUDP(network, addr)
}

// DefaultDialer is the default [net.Dialer] used by [Stdlib].
var DefaultDialer = &net.Dialer{}

// dialer returns a suitable [net.Dialer].
func (s *Stdlib) dialer() *net.Dialer {
	if s.Dialer != nil {
		return s.Dialer
	}
	return DefaultDialer
}

// resolver returns a suitable [net.Resolver].
func (s *Stdlib) resolver() *net.Resolver {
	if s.Resolver != nil {
		return s.Resolver
	}
	return net.DefaultResolver
}
