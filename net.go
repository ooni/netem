package netem

//
// Full replacement for [net]
//

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// Net is a drop-in replacement for the [net] package. The zero
// value is invalid; please init all the MANDATORY fields.
type Net struct {
	// Stack is the MANDATORY underlying stack.
	Stack UnderlyingNetwork
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
