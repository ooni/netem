package netem

//
// UNetStack: userspace network stack.
//

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

// UNetStack is a network stack in user space. The zero value is
// invalid; please, use [NewUNetStack] to construct.
//
// Because [UNetStack] implements [UnderlyingNetwork], you can use
// it to perform the following operations:
//
// - connect TCP/UDP sockets using [UNetStack.DialContext];
//
// - create listening UDP sockets using [UNetStack.ListenUDP];
//
// - create listening TCP sockets using [UNetStack.ListenTCP];
//
// - perform getaddrinfo like DNS lookups using [UNetStack.GetaddrinfoLookupANY];
//
// Use [UNetStack.NIC] to obtain a [NIC] to read and write the [Frames]
// produced by using the network stack as the [UnderlyingNetwork].
type UNetStack struct {
	// ns is the GVisor network stack.
	ns *gvisorStack

	// mitmConfig allows generating X.509 certificates on the fly.
	mitmConfig *TLSMITMConfig

	// resoAddr is the resolver IPv4 address.
	resoAddr netip.Addr
}

var (
	_ HTTPUnderlyingNetwork = &UNetStack{}
	_ NIC                   = &UNetStack{}
	_ UnderlyingNetwork     = &UNetStack{}
)

// NewUNetStack constructs a new [UNetStack] instance.
//
// Arguments:
//
// - logger is the logger to use;
//
// - MTU is the MTU to use (you MUST use at least 1252 bytes if you
// want to use github.com/lucas-clemente/quic-go);
//
// - stackAddress is the IPv4 address to assign to the stack;
//
// - cfg contains TLS MITM configuration;
//
// - resolverAddress is the IPv4 address of the resolver.
func NewUNetStack(
	logger Logger,
	MTU uint32,
	stackAddress string,
	cfg *TLSMITMConfig,
	resolverAddress string,
) (*UNetStack, error) {
	// parse the stack address
	stackAddr, err := netip.ParseAddr(stackAddress)
	if err != nil {
		return nil, err
	}
	if !stackAddr.Is4() {
		return nil, syscall.EAFNOSUPPORT
	}

	// parse the resolver address
	resolverAddr, err := netip.ParseAddr(resolverAddress)
	if err != nil {
		return nil, err
	}
	if !resolverAddr.Is4() {
		return nil, syscall.EAFNOSUPPORT
	}

	// create userspace network stack
	ns, err := newGVisorStack(logger, stackAddr, MTU)
	if err != nil {
		return nil, err
	}

	// fill and return the network stack
	stack := &UNetStack{
		ns:         ns,
		mitmConfig: cfg,
		resoAddr:   resolverAddr,
	}
	return stack, nil
}

// Logger implements HTTPUnderlyingNetwork
func (gs *UNetStack) Logger() Logger {
	return gs.ns.logger
}

// ServerTLSConfig returns the [tls.Config] we should use on the server side.
func (gs *UNetStack) ServerTLSConfig() *tls.Config {
	return gs.mitmConfig.TLSConfig()
}

// FrameAvailable implements NIC
func (gs *UNetStack) FrameAvailable() <-chan any {
	return gs.ns.FrameAvailable()
}

// ReadFrameNonblocking implements NIC
func (gs *UNetStack) ReadFrameNonblocking() (*Frame, error) {
	return gs.ns.ReadFrameNonblocking()
}

// StackClosed implements NIC
func (gs *UNetStack) StackClosed() <-chan any {
	return gs.ns.StackClosed()
}

// IPAddress implements NIC
func (gs *UNetStack) IPAddress() string {
	return gs.ns.IPAddress()
}

// InterfaceName implements NIC
func (gs *UNetStack) InterfaceName() string {
	return gs.ns.InterfaceName()
}

// WriteFrame implements NIC
func (gs *UNetStack) WriteFrame(frame *Frame) error {
	return gs.ns.WriteFrame(frame)
}

// Close shuts down the virtual network stack.
func (gs *UNetStack) Close() error {
	return gs.ns.Close()
}

// DefaultCertPool implements UnderlyingNetwork.
func (gs *UNetStack) DefaultCertPool() *x509.CertPool {
	return gs.mitmConfig.CertPool()
}

// DialContext implements UnderlyingNetwork.
func (gs *UNetStack) DialContext(
	ctx context.Context, network string, address string) (net.Conn, error) {
	var (
		conn net.Conn
		err  error
	)

	// parse the address into a [netip.Addr]
	addrport, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, err
	}

	// determine what "dial" actualls means in this context (sorry)
	switch network {
	case "tcp":
		conn, err = gs.ns.DialContextTCPAddrPort(ctx, addrport)

	case "udp":
		conn, err = gs.ns.DialUDPAddrPort(netip.AddrPort{}, addrport)

	default:
		return nil, syscall.EPROTOTYPE
	}

	// make sure we return an error on failure
	if err != nil {
		return nil, mapUNetError(err)
	}

	// wrap returned connection to correctly map errors
	return &unetConnWrapper{conn}, nil
}

// GetaddrinfoLookupANY implements UnderlyingNetwork.
func (gs *UNetStack) GetaddrinfoLookupANY(ctx context.Context, domain string) ([]string, string, error) {
	// shortcircuit IP addresses
	if net.ParseIP(domain) != nil {
		return []string{domain}, "", nil
	}

	// create the query message
	query := NewDNSRequestA(domain)

	// perform the DNS round trip
	resp, err := DNSRoundTrip(ctx, gs, gs.resoAddr.String(), query)
	if err != nil {
		return nil, "", err
	}

	// parse the results into a getaddrinfo result
	return DNSParseResponse(query, resp)
}

// GetaddrinfoResolverNetwork implements UnderlyingNetwork
func (gs *UNetStack) GetaddrinfoResolverNetwork() string {
	return "getaddrinfo" // pretend we are calling the getaddrinfo(3) func
}

// ListenUDP implements UnderlyingNetwork.
func (gs *UNetStack) ListenUDP(network string, addr *net.UDPAddr) (UDPLikeConn, error) {
	if network != "udp" {
		return nil, syscall.EPROTOTYPE
	}

	// convert addr to [netip.AddrPort]
	ipaddr, good := netip.AddrFromSlice(addr.IP)
	if !good {
		return nil, syscall.EADDRNOTAVAIL
	}
	addrport := netip.AddrPortFrom(ipaddr, uint16(addr.Port))

	pconn, err := gs.ns.DialUDPAddrPort(addrport, netip.AddrPort{})
	if err != nil {
		return nil, mapUNetError(err)
	}

	return &unetPacketConnWrapper{pconn}, nil
}

// ListenTCP implements UnderlyingNetwork
func (gs *UNetStack) ListenTCP(network string, addr *net.TCPAddr) (net.Listener, error) {
	if network != "tcp" {
		return nil, syscall.EPROTOTYPE
	}

	// convert addr to [netip.AddrPort]
	ipaddr, good := netip.AddrFromSlice(addr.IP)
	if !good {
		return nil, syscall.EADDRNOTAVAIL
	}
	addrport := netip.AddrPortFrom(ipaddr, uint16(addr.Port))

	listener, err := gs.ns.ListenTCPAddrPort(addrport)
	if err != nil {
		return nil, mapUNetError(err)
	}

	return &unetListenerWrapper{listener}, nil
}

// unetSuffixToError maps a gvisor error suffix to an stdlib error.
type unetSuffixToError struct {
	// suffix is the unet err.Error() suffix.
	suffix string

	// err is generally a syscall error but it could
	// also be any other stdlib error.
	err error
}

// allUNetSyscallErrors defines [unetSuffixToError] rules for all the
// errors emitted by unet that matter to measuring censorship.
//
// See https://github.com/google/gvisor/blob/master/pkg/tcpip/errors.go
//
// See https://github.com/google/gvisor/blob/master/pkg/syserr/netstack.go
var allUNetSyscallErrors = []*unetSuffixToError{{
	suffix: "endpoint is closed for receive",
	err:    net.ErrClosed,
}, {
	suffix: "endpoint is closed for send",
	err:    net.ErrClosed,
}, {
	suffix: "connection aborted",
	err:    syscall.ECONNABORTED,
}, {
	suffix: "connection was refused",
	err:    syscall.ECONNREFUSED,
}, {
	suffix: "connection reset by peer",
	err:    syscall.ECONNRESET,
}, {
	suffix: "network is unreachable",
	err:    syscall.ENETUNREACH,
}, {
	suffix: "no route to host",
	err:    syscall.EHOSTUNREACH,
}, {
	suffix: "host is down",
	err:    syscall.EHOSTDOWN,
}, {
	suffix: "machine is not on the network",
	err:    syscall.ENETDOWN,
}, {
	suffix: "operation timed out",
	err:    syscall.ETIMEDOUT,
}, {
	suffix: "endpoint is in invalid state",
	err:    syscall.EINVAL,
}}

// mapUNetError maps a unet error to an stdlib error.
func mapUNetError(err error) error {
	if err != nil {
		estring := err.Error()
		for _, entry := range allUNetSyscallErrors {
			if strings.HasSuffix(estring, entry.suffix) {
				return entry.err
			}
		}
	}
	return err
}

// unetConnWrapper wraps a [net.Conn] to remap unet errors
// so that we can emulate stdlib errors.
type unetConnWrapper struct {
	c net.Conn
}

var _ net.Conn = &unetConnWrapper{}

// Close implements net.Conn
func (gcw *unetConnWrapper) Close() error {
	return gcw.c.Close()
}

// LocalAddr implements net.Conn
func (gcw *unetConnWrapper) LocalAddr() net.Addr {
	return gcw.c.LocalAddr()
}

// Read implements net.Conn
func (gcw *unetConnWrapper) Read(b []byte) (n int, err error) {
	count, err := gcw.c.Read(b)
	return count, mapUNetError(err)
}

// RemoteAddr implements net.Conn
func (gcw *unetConnWrapper) RemoteAddr() net.Addr {
	return gcw.c.RemoteAddr()
}

// SetDeadline implements net.Conn
func (gcw *unetConnWrapper) SetDeadline(t time.Time) error {
	return gcw.c.SetDeadline(t)
}

// SetReadDeadline implements net.Conn
func (gcw *unetConnWrapper) SetReadDeadline(t time.Time) error {
	return gcw.c.SetReadDeadline(t)
}

// SetWriteDeadline implements net.Conn
func (gcw *unetConnWrapper) SetWriteDeadline(t time.Time) error {
	return gcw.c.SetWriteDeadline(t)
}

// Write implements net.Conn
func (gcw *unetConnWrapper) Write(b []byte) (n int, err error) {
	count, err := gcw.c.Write(b)
	return count, mapUNetError(err)
}

// unetPacketConnWrapper wraps a [model.UDPLikeConn] such that we can use
// this connection with lucas-clemente/quic-go and remaps unet errors to
// emulate actual stdlib errors.
type unetPacketConnWrapper struct {
	c *gonet.UDPConn
}

var (
	_ UDPLikeConn     = &unetPacketConnWrapper{}
	_ syscall.RawConn = &unetPacketConnWrapper{}
)

// Close implements model.UDPLikeConn
func (gpcw *unetPacketConnWrapper) Close() error {
	return gpcw.c.Close()
}

// LocalAddr implements model.UDPLikeConn
func (gpcw *unetPacketConnWrapper) LocalAddr() net.Addr {
	return gpcw.c.LocalAddr()
}

// ReadFrom implements model.UDPLikeConn
func (gpcw *unetPacketConnWrapper) ReadFrom(p []byte) (int, net.Addr, error) {
	count, addr, err := gpcw.c.ReadFrom(p)
	return count, addr, mapUNetError(err)
}

// SetDeadline implements model.UDPLikeConn
func (gpcw *unetPacketConnWrapper) SetDeadline(t time.Time) error {
	return gpcw.c.SetDeadline(t)
}

// SetReadDeadline implements model.UDPLikeConn
func (gpcw *unetPacketConnWrapper) SetReadDeadline(t time.Time) error {
	return gpcw.c.SetReadDeadline(t)
}

// SetWriteDeadline implements model.UDPLikeConn
func (gpcw *unetPacketConnWrapper) SetWriteDeadline(t time.Time) error {
	return gpcw.c.SetWriteDeadline(t)
}

// WriteTo implements model.UDPLikeConn
func (gpcw *unetPacketConnWrapper) WriteTo(p []byte, addr net.Addr) (int, error) {
	count, err := gpcw.c.WriteTo(p, addr)
	return count, mapUNetError(err)
}

// Implementation note: the following function calls are all stubs and they
// should nonetheless work with lucas-clemente/quic-go.

// SetReadBuffer implements model.UDPLikeConn
func (gpcw *unetPacketConnWrapper) SetReadBuffer(bytes int) error {
	return nil
}

// SyscallConn implements model.UDPLikeConn
func (gpcw *unetPacketConnWrapper) SyscallConn() (syscall.RawConn, error) {
	return gpcw, nil
}

// Control implements syscall.RawConn
func (gpcw *unetPacketConnWrapper) Control(f func(fd uintptr)) error {
	return nil
}

// Read implements syscall.RawConn
func (gpcw *unetPacketConnWrapper) Read(f func(fd uintptr) (done bool)) error {
	return nil
}

// Write implements syscall.RawConn
func (gpcw *unetPacketConnWrapper) Write(f func(fd uintptr) (done bool)) error {
	return nil
}

// unetListenerWrapper wraps a [net.Listener] and maps unet
// errors to the corresponding stdlib errors.
type unetListenerWrapper struct {
	l *gonet.TCPListener
}

var _ net.Listener = &unetListenerWrapper{}

// Accept implements net.Listener
func (glw *unetListenerWrapper) Accept() (net.Conn, error) {
	conn, err := glw.l.Accept()
	if err != nil {
		return nil, mapUNetError(err)
	}
	return &unetConnWrapper{conn}, nil
}

// Addr implements net.Listener
func (glw *unetListenerWrapper) Addr() net.Addr {
	return glw.l.Addr()
}

// Close implements net.Listener
func (glw *unetListenerWrapper) Close() error {
	return glw.l.Close()
}
