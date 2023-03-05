package netem

//
// Full replacement for [net]
//

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
)

// NetUnderlyingNetwork is the [UnderlyingNetwork] used by a [Net].
type NetUnderlyingNetwork interface {
	UnderlyingNetwork
	ServerTLSConfig() *tls.Config
}

// Net is a drop-in replacement for the [net] package. The zero
// value is invalid; please init all the MANDATORY fields.
type Net struct {
	// Stack is the MANDATORY underlying stack.
	Stack NetUnderlyingNetwork
}

// ErrDial contains all the errors occurred during a [DialContext] operation.
type ErrDial struct {
	// Errors contains the list of errors.
	Errors []error
}

var _ error = &ErrDial{}

// Error implements error
func (e *ErrDial) Error() string {
	var b strings.Builder
	b.WriteString("dial failed: ")
	for index, err := range e.Errors {
		b.WriteString(err.Error())
		if index < len(e.Errors)-1 {
			b.WriteString("; ")
		}
	}
	return b.String()
}

// DialContext is a drop-in replacement for [net.Dialer.DialContext].
func (n *Net) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	// determine the domain or IP address we're connecting to
	domain, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	// make sure we have IP addresses to try
	var addresses []string
	switch v := net.ParseIP(domain); v {
	default:
		addresses = append(addresses, domain)
	case nil:
		addresses, err = n.LookupHost(ctx, domain)
		if err != nil {
			return nil, err
		}
	}

	// try each available address
	errlist := &ErrDial{}
	for _, ip := range addresses {
		endpoint := net.JoinHostPort(ip, port)
		conn, err := n.Stack.DialContext(ctx, network, endpoint)
		if err != nil {
			errlist.Errors = append(errlist.Errors, fmt.Errorf("%s: %w", endpoint, err))
			continue
		}
		return conn, nil
	}

	return nil, errlist
}

// DialTLSContext is like [Net.DialContext] but also performs a TLS handshake.
func (n *Net) DialTLSContext(ctx context.Context, network, address string) (net.Conn, error) {
	hostname, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	conn, err := n.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{
		RootCAs:    n.Stack.DefaultCertPool(),
		NextProtos: nil, // TODO(bassosimone): automatically generate the right ALPN
		ServerName: hostname,
	}
	tc := tls.Client(conn, config)
	if err := tc.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return tc, nil
}

// LookupHost is a drop-in replacement for [net.Resolver.LookupHost].
func (n *Net) LookupHost(ctx context.Context, domain string) ([]string, error) {
	addrs, _, err := n.Stack.GetaddrinfoLookupANY(ctx, domain)
	return addrs, err
}

// LookupCNAME is a drop-in replacement for [net.Resolver.LookupCNAME].
func (n *Net) LookupCNAME(ctx context.Context, domain string) (string, error) {
	_, cname, err := n.Stack.GetaddrinfoLookupANY(ctx, domain)
	return cname, err
}

// ListenTCP is a drop-in replacement for [net.ListenTCP].
func (n *Net) ListenTCP(network string, addr *net.TCPAddr) (net.Listener, error) {
	return n.Stack.ListenTCP(network, addr)
}

// ListenUDP is a drop-in replacement for [net.ListenUDP].
func (n *Net) ListenUDP(network string, addr *net.UDPAddr) (UDPLikeConn, error) {
	return n.Stack.ListenUDP(network, addr)
}

// ListenTLS is a replacement for [tls.Listen] that uses the underlying
// stack's TLS MITM capabilities during the TLS handshake.
func (n *Net) ListenTLS(network string, laddr *net.TCPAddr) (net.Listener, error) {
	listener, err := n.ListenTCP(network, laddr)
	if err != nil {
		return nil, err
	}
	lw := &netListenerTLS{
		listener: listener,
		stack:    n.Stack,
	}
	return lw, nil
}

// netListenerTLS is a TLS listener.
type netListenerTLS struct {
	listener net.Listener
	stack    NetUnderlyingNetwork
}

var _ net.Listener = &netListenerTLS{}

// Accept implements net.Listener
func (lw *netListenerTLS) Accept() (net.Conn, error) {
	conn, err := lw.listener.Accept()
	if err != nil {
		return nil, err
	}
	config := lw.stack.ServerTLSConfig()
	tc := tls.Server(conn, config)
	if err := tc.HandshakeContext(context.Background()); err != nil {
		conn.Close()
		return nil, err
	}
	return tc, nil
}

// Addr implements net.Listener
func (lw *netListenerTLS) Addr() net.Addr {
	return lw.listener.Addr()
}

// Close implements net.Listener
func (lw *netListenerTLS) Close() error {
	return lw.listener.Close()
}
