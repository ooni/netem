package netem

//
// GVisor-based userspace network stack.
//
// Adapted from https://github.com/WireGuard/wireguard-go
//
// SPDX-License-Identifier: MIT
//

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// gvisorStack is a TCP/IP stack in userspace. Seen from above this
// stack allows creating TCP and UDP connections. Seen from below, it
// allows one to read and write IP packets. The zero value of this
// structure is invalid; please, use [newGVisorStack] to instantiate.
type gvisorStack struct {
	// closeOnce ensures that Close has once semantics.
	closeOnce sync.Once

	// closed is closed by Close and signals that we should
	// not perform any further TCP/IP operation.
	closed chan any

	// endpoint is the endpoint receiving gvisor notifications.
	endpoint *channel.Endpoint

	// incomingPacket is the channel posted by GVisor
	// when there is an incoming IP packet.
	incomingPacket chan any

	// ipAddress is the IP address we're using.
	ipAddress netip.Addr

	// logger is the logger to use.
	logger Logger

	// name is the interface name.
	name string

	// stack is the network stack in userspace.
	stack *stack.Stack
}

// newGVisorStack creates a new [gvisorStack] instance.
func newGVisorStack(logger Logger, A netip.Addr, MTU uint32) (*gvisorStack, error) {

	// create options for the new stack
	stackOptions := stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
		},
		HandleLocal: true,
	}

	// create the stack instance
	name := newNICName()
	gvs := &gvisorStack{
		closeOnce:      sync.Once{},
		closed:         make(chan any),
		endpoint:       channel.New(1024, MTU, ""),
		name:           name,
		ipAddress:      A,
		incomingPacket: make(chan any),
		logger:         logger,
		stack:          stack.New(stackOptions),
	}

	// register network as the notification target for gvisor
	gvs.endpoint.AddNotify(gvs)

	// create a NIC to attach to this stack
	if err := gvs.stack.CreateNIC(1, gvs.endpoint); err != nil {
		return nil, errors.New(err.String())
	}

	// configure the IPv4 address for the NIC we created
	protoAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.Address(A.AsSlice()).WithPrefix(),
	}
	if err := gvs.stack.AddProtocolAddress(1, protoAddr, stack.AddressProperties{}); err != nil {
		return nil, errors.New(err.String())
	}

	// install the IPv4 address in the routing table
	gvs.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})

	logger.Infof("netem: ifconfig %s mtu %d", name, MTU)
	logger.Infof("netem: ifconfig %s %s up", name, A)
	logger.Infof("netem: ip route add default dev %s", name)
	return gvs, nil
}

var _ NIC = &gvisorStack{}

// IPAddress implements NIC
func (gvs *gvisorStack) IPAddress() string {
	return gvs.ipAddress.String()
}

// FrameAvailable implements NIC
func (gvs *gvisorStack) FrameAvailable() <-chan any {
	return gvs.incomingPacket
}

// ReadFrameNonblocking implements NIC
func (gvs *gvisorStack) ReadFrameNonblocking() (*Frame, error) {
	// avoid reading if we've been closed
	select {
	case <-gvs.closed:
		return nil, io.EOF
	default:
	}

	// obtain the packet buffer from the endpoint
	pktbuf := gvs.endpoint.Read()
	if pktbuf.IsNil() {
		return nil, syscall.EAGAIN
	}
	view := pktbuf.ToView()
	pktbuf.DecRef()

	// read the actual packet payload
	buffer := make([]byte, gvs.endpoint.MTU())
	count, err := view.Read(buffer)
	if err != nil {
		return nil, err
	}

	// prepare the outgoing frame
	payload := buffer[:count]
	frame := &Frame{
		Deadline: time.Now(),
		Payload:  payload[:count],
	}
	return frame, nil
}

// InterfaceName implements NIC.
func (gvs *gvisorStack) InterfaceName() string {
	return gvs.name
}

// StackClosed implements NIC
func (gvs *gvisorStack) StackClosed() <-chan any {
	return gvs.closed
}

// WriteNotify implements channel.Notification. GVisor will call this
// callback function everytime there's a new readable packet.
func (gvs *gvisorStack) WriteNotify() {
	gvs.incomingPacket <- true
}

// WriteFrame implements NIC
func (gvs *gvisorStack) WriteFrame(frame *Frame) error {
	// there is clearly a race condition with closing but the intent is just
	// to behave and return ErrClose long after we've been closed
	select {
	case <-gvs.closed:
		return net.ErrClosed
	default:
	}

	// the following code is already ready for supporting IPv6
	// should we want to do that in the future
	packet := frame.Payload
	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: bufferv2.MakeWithData(packet)})
	switch packet[0] >> 4 {
	case 4:
		gvs.endpoint.InjectInbound(header.IPv4ProtocolNumber, pkb)
	case 6:
		gvs.endpoint.InjectInbound(header.IPv6ProtocolNumber, pkb)
	}

	return nil
}

// Close ensures that we cannot send and recv additional packets and
// that we cannot establish new TCP/UDP connections.
func (gvs *gvisorStack) Close() error {
	gvs.closeOnce.Do(func() {
		// synchronize with other users (MUST be first)
		close(gvs.closed)

		// tell the user this interface has been closed
		gvs.logger.Infof("netem: ifconfig %s down", gvs.name)
		gvs.logger.Info("netem: ip route del default")
	})
	return nil
}

// DialContextTCPAddrPort establishes a new TCP connection.
func (gvs *gvisorStack) DialContextTCPAddrPort(
	ctx context.Context, addr netip.AddrPort) (*gonet.TCPConn, error) {
	fa, pn := gvisorConvertToFullAddr(addr)
	return gonet.DialContextTCP(ctx, gvs.stack, fa, pn)
}

// ListenTCPAddrPort creates a new listening TCP socket.
func (gvs *gvisorStack) ListenTCPAddrPort(addr netip.AddrPort) (*gonet.TCPListener, error) {
	fa, pn := gvisorConvertToFullAddr(addr)
	return gonet.ListenTCP(gvs.stack, fa, pn)
}

// DialUDPAddrPort allows to create UDP sockets. Using a nil
// raddr is equivalent to [net.ListenUDP]. Using nil laddr instead
// is equivalent to [net.DialContext] with an "udp" network.
func (gvs *gvisorStack) DialUDPAddrPort(laddr, raddr netip.AddrPort) (*gonet.UDPConn, error) {
	var lfa, rfa *tcpip.FullAddress
	var pn tcpip.NetworkProtocolNumber

	if laddr.IsValid() || laddr.Port() > 0 {
		var addr tcpip.FullAddress
		addr, pn = gvisorConvertToFullAddr(laddr)
		lfa = &addr
	}

	if raddr.IsValid() || raddr.Port() > 0 {
		var addr tcpip.FullAddress
		addr, pn = gvisorConvertToFullAddr(raddr)
		rfa = &addr
	}

	return gonet.DialUDP(gvs.stack, lfa, rfa, pn)
}

// gvisorConvertToFullAddr is a convenience function for converting
// a [netip.AddrPort] to the kind of addrs used by GVisor.
func gvisorConvertToFullAddr(endpoint netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	var protoNumber tcpip.NetworkProtocolNumber

	// the following code is already ready for supporting IPv6
	// should we want to do that in the future
	if endpoint.Addr().Is4() {
		protoNumber = ipv4.ProtocolNumber
	} else {
		protoNumber = ipv6.ProtocolNumber
	}

	fa := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.Address(endpoint.Addr().AsSlice()),
		Port: endpoint.Port(),
	}

	return fa, protoNumber
}
