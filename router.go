package netem

//
// Packet routing
//

import (
	"errors"
	"sync"
)

// RouterPort is a port of a [Router]. The zero value is invalid, use
// the [NewRouterPort] constructor to instantiate.
type RouterPort struct {
	// closeOnce provides once semantics for the Close method
	closeOnce sync.Once

	// closed is closed when we close this port
	closed chan any

	// ifaceName is the interface name
	ifaceName string

	// logger is the logger to use
	logger Logger

	// outgoingMu protects outgoingQueue
	outgoingMu sync.Mutex

	// outgoingNotify is posted each time a new packet is queued
	outgoingNotify chan any

	// outgoingQueue is the outgoing queue
	outgoingQueue [][]byte

	// router is the router.
	router *Router
}

// NewRouterPort creates a new [RouterPort] for a given [Router].
func NewRouterPort(router *Router) *RouterPort {
	const maxNotifications = 1024
	port := &RouterPort{
		closeOnce:      sync.Once{},
		closed:         make(chan any),
		logger:         router.logger,
		ifaceName:      newNICName(),
		outgoingMu:     sync.Mutex{},
		outgoingNotify: make(chan any, maxNotifications),
		outgoingQueue:  [][]byte{},
		router:         router,
	}
	port.logger.Infof("netem: ifconfig %s up", port.ifaceName)
	return port
}

var _ NIC = &RouterPort{}

// writeOutgoingPacket is the function a [Router] calls
// to write an outgoing packet of this port.
func (sp *RouterPort) writeOutgoingPacket(packet []byte) error {
	// enqueue
	sp.outgoingMu.Lock()
	sp.outgoingQueue = append(sp.outgoingQueue, packet)
	sp.outgoingMu.Unlock()

	// notify
	select {
	case <-sp.closed:
		return ErrStackClosed
	case sp.outgoingNotify <- true:
		return nil
	default:
		return ErrPacketDropped
	}
}

// FrameAvailable implements NIC
func (sp *RouterPort) FrameAvailable() <-chan any {
	return sp.outgoingNotify
}

// ReadFrameNonblocking implements NIC
func (sp *RouterPort) ReadFrameNonblocking() (*Frame, error) {
	// honour the port-closed flag
	select {
	case <-sp.closed:
		return nil, ErrStackClosed
	default:
		// fallthrough
	}

	// check whether we can read from the queue
	defer sp.outgoingMu.Unlock()
	sp.outgoingMu.Lock()
	if len(sp.outgoingQueue) <= 0 {
		return nil, ErrNoPacket
	}

	// dequeue packet
	packet := sp.outgoingQueue[0]
	sp.outgoingQueue = sp.outgoingQueue[1:]

	// wrap packet with a frame
	frame := NewFrame(packet)
	return frame, nil
}

// StackClosed implements NIC
func (sp *RouterPort) StackClosed() <-chan any {
	return sp.closed
}

// Close implements NIC
func (sp *RouterPort) Close() error {
	sp.closeOnce.Do(func() {
		sp.logger.Infof("netem: ifconfig %s down", sp.ifaceName)
		close(sp.closed)
	})
	return nil
}

// IPAddress implements NIC
func (sp *RouterPort) IPAddress() string {
	return "0.0.0.0"
}

// InterfaceName implements NIC
func (sp *RouterPort) InterfaceName() string {
	return sp.ifaceName
}

// ErrPacketDropped indicates that a packet was dropped.
var ErrPacketDropped = errors.New("netem: packet was dropped")

// WriteFrame implements NIC
func (sp *RouterPort) WriteFrame(frame *Frame) error {
	return sp.router.tryRoute(frame.Payload, frame.Flags)
}

// Router routes traffic between [RouterPort]s. The zero value of this
// structure isn't invalid; construct using [NewRouter].
type Router struct {
	// logger is the Logger we're using.
	logger Logger

	// mu provides mutual exclusion.
	mu sync.Mutex

	// table is the routing table.
	table map[string]*RouterPort
}

// NewRouter creates a new [Router] instance.
func NewRouter(logger Logger) *Router {
	return &Router{
		logger: logger,
		mu:     sync.Mutex{},
		table:  map[string]*RouterPort{},
	}
}

// AddRoute adds a route to the routing table.
func (r *Router) AddRoute(destIP string, destPort *RouterPort) {
	r.logger.Infof("netem: route add %s/32 %s", destIP, destPort.ifaceName)
	r.mu.Lock()
	r.table[destIP] = destPort
	r.mu.Unlock()
}

// tryRoute attempts to route a raw packet.
func (r *Router) tryRoute(rawInput []byte, flags int64) error {
	// parse the packet
	packet, err := DissectPacket(rawInput)
	if err != nil {
		r.logger.Warnf("netem: tryRoute: %s", err.Error())
		return err
	}

	// check whether we should drop this packet
	if ttl := packet.TimeToLive(); ttl <= 0 {
		r.logger.Warn("netem: tryRoute: TTL exceeded in transit")
		return ErrPacketDropped
	}
	packet.DecrementTimeToLive()

	// check whether we should reflect this frame
	if flags&FrameFlagRST != 0 {
		segment, err := reflectDissectedTCPSegmentWithRSTFlag(packet)
		if err == nil {
			_ = r.tryRoute(segment, 0)
			// fallthrough
		}
		// fallthrough
	}

	// figure out the interface where to emit the packet
	destAddr := packet.DestinationIPAddress()
	r.mu.Lock()
	destPort := r.table[destAddr]
	r.mu.Unlock()
	if destPort == nil {
		r.logger.Warnf("netem: tryRoute: %s: no route to host", destAddr)
		return ErrPacketDropped
	}

	// serialize a TCP or UDP packet while ignoring other protocols
	rawOutput, err := packet.Serialize()
	if err != nil {
		r.logger.Warnf("netem: tryRoute: %s", err.Error())
		return err
	}

	return destPort.writeOutgoingPacket(rawOutput)
}
