package netem

//
// Data model
//

import (
	"context"
	"crypto/x509"
	"net"
	"syscall"
	"time"
)

// Frame contains an IPv4 or IPv6 packet.
type Frame struct {
	// Deadline is the time when this frame should be delivered.
	Deadline time.Time

	// Payload contains the packet payload.
	Payload []byte
}

// FrameReader allows one to read incoming frames.
type FrameReader interface {
	// FrameAvailable returns a channel that becomes readable
	// when a new frame has arrived.
	FrameAvailable() <-chan any

	// ReadFrameNonblocking reads an incoming frame. You should only call
	// this function after FrameAvailable has been readable. This function
	// returns one of the following errors:
	//
	// - ErrStackClosed if the underlying stack has been closed;
	//
	// - ErrNoPacket if no packet is available.
	//
	// Callers should ignore ErrNoPacket and try reading again later.
	ReadFrameNonblocking() (*Frame, error)

	// StackClosed returns a channel that becomes readable when the
	// userspace network stack has been closed.
	StackClosed() <-chan any
}

// Logger is the logger we're using.
type Logger interface {
	// Debugf formats and emits a debug message.
	Debugf(format string, v ...any)

	// Debug emits a debug message.
	Debug(message string)

	// Infof formats and emits an informational message.
	Infof(format string, v ...any)

	// Info emits an informational message.
	Info(message string)

	// Warnf formats and emits a warning message.
	Warnf(format string, v ...any)

	// Warn emits a warning message.
	Warn(message string)
}

// NIC is a network interface card with which you can send and receive [Frame]s.
type NIC interface {
	// A NIC implements FrameReader
	FrameReader

	// Close closes this network interface.
	Close() error

	// IPAddress returns the IP address assigned to the NIC.
	IPAddress() string

	// InterfaceName returns the name of the NIC.
	InterfaceName() string

	// WriteFrame writes a frame or returns an error. This function
	// returns ErrStackClosed when the underlying stack has been closed.
	WriteFrame(frame *Frame) error
}

// UDPLikeConn is a net.PacketConn with some extra functions
// required to convince the QUIC library (lucas-clemente/quic-go)
// to inflate the receive buffer of the connection.
//
// The QUIC library will treat this connection as a "dumb"
// net.PacketConn, calling its ReadFrom and WriteTo methods
// as opposed to more efficient methods that are available
// under Linux and (maybe?) FreeBSD.
//
// It seems fine to avoid performance optimizations, because
// they would complicate the implementation on our side and
// our use cases (blocking and heavy throttling) do not seem
// to require such optimizations.
//
// See https://github.com/ooni/probe/issues/1754 for a more
// comprehensive discussion of UDPLikeConn.
type UDPLikeConn interface {
	// An UDPLikeConn is a net.PacketConn conn.
	net.PacketConn

	// SetReadBuffer allows setting the read buffer.
	SetReadBuffer(bytes int) error

	// SyscallConn returns a conn suitable for calling syscalls,
	// which is also instrumental to setting the read buffer.
	SyscallConn() (syscall.RawConn, error)
}

// UnderlyingNetwork replaces for functions in the [net] package.
type UnderlyingNetwork interface {
	// DefaultCertPool returns the underlying cert pool to be used.
	DefaultCertPool() *x509.CertPool

	// DialContext dials a TCP or UDP connection. Unlike [net.DialContext], this
	// function does not implement dialing when address contains a domain.
	DialContext(ctx context.Context, network, address string) (net.Conn, error)

	// GetaddrinfoLookupANY is like [net.Resolver.LookupHost] except that it
	// also returns to the caller the CNAME when it is available.
	GetaddrinfoLookupANY(ctx context.Context, domain string) ([]string, string, error)

	// GetaddrinfoResolverNetwork returns the resolver network.
	GetaddrinfoResolverNetwork() string

	// ListenTCP creates a new listening TCP socket.
	ListenTCP(network string, addr *net.TCPAddr) (net.Listener, error)

	// ListenUDP creates a new listening UDP socket. The [UDPLikeConn] returned
	// by this function is a best effort attempt to emulate a [net.UDPConn] that
	// works with the github.com/lucas-clemente/quic-go library.
	ListenUDP(network string, addr *net.UDPAddr) (UDPLikeConn, error)
}
