package netem

//
// Packet routing
//

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/apex/log"
)

// RouterPort is a port of a [Router]. The zero value is invalid, use
// the [NewRouterPort] constructor to instantiate.
type RouterPort struct {
	// closeOnce provides once semantics for the Close method
	closeOnce sync.Once

	// closed is closed when we close this port
	closed chan any

	// incoming is the router channel for incoming packets
	incoming chan []byte

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
}

// NewRouterPort creates a new [RouterPort] for a given [Router].
func NewRouterPort(router *Router) *RouterPort {
	port := &RouterPort{
		closeOnce:      sync.Once{},
		closed:         make(chan any),
		incoming:       router.incoming,
		logger:         router.logger,
		ifaceName:      newNICName(),
		outgoingMu:     sync.Mutex{},
		outgoingNotify: make(chan any),
		outgoingQueue:  [][]byte{},
	}
	port.logger.Infof("netem: ifconfig %s up", port.ifaceName)
	return port
}

var _ NIC = &RouterPort{}

// WriteOutgoingPacket is the function a [Router] calls
// to write an outgoing packet of this port.
func (sp *RouterPort) WriteOutgoingPacket(packet []byte) error {
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

	// return the front packet wrapped by a frame
	frame := &Frame{
		Deadline: time.Now(),
		Payload:  packet,
	}
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
	select {
	case <-sp.closed:
		return ErrStackClosed
	case sp.incoming <- frame.Payload:
		return nil
	default:
		return ErrPacketDropped
	}
}

// Router routes traffic between [RouterPort]s. The zero value of this
// structure isn't invalid; construct using [NewRouter].
type Router struct {
	// closeOnce allows to provide "once" semantics for close.
	closeOnce sync.Once

	// cancel allows to stop background workers.
	cancel context.CancelFunc

	// incoming receives incoming packets.
	incoming chan []byte

	// logger is the Logger we're using.
	logger Logger

	// mu provides mutual exclusion.
	mu sync.Mutex

	// table is the routing table.
	table map[string]*RouterPort

	// wg allows us to wait for the background goroutines to join.
	wg *sync.WaitGroup
}

// NewRouter creates a new [Router] instance.
func NewRouter(logger Logger) *Router {
	ctx, cancel := context.WithCancel(context.Background())
	const incomingBuffer = 1024
	r := &Router{
		closeOnce: sync.Once{},
		cancel:    cancel,
		incoming:  make(chan []byte, incomingBuffer),
		logger:    logger,
		mu:        sync.Mutex{},
		table:     map[string]*RouterPort{},
		wg:        &sync.WaitGroup{},
	}

	// create a bunch of workers
	const workers = 8
	for idx := 0; idx < workers; idx++ {
		r.wg.Add(1)
		go r.workerMain(ctx, idx)
	}

	return r
}

// AddRoute adds a route to the routing table.
func (r *Router) AddRoute(destIP string, destPort *RouterPort) {
	log.Infof("netem: route add %s/32 %s", destIP, destPort.ifaceName)
	r.mu.Lock()
	r.table[destIP] = destPort
	r.mu.Unlock()
}

// Close closes all the resources managed by a router
func (r *Router) Close() error {
	r.closeOnce.Do(func() {
		r.cancel()
		r.wg.Wait()
	})
	return nil
}

// workerMain is the main function of a router worker.
func (r *Router) workerMain(ctx context.Context, idx int) {
	defer r.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case packetIn := <-r.incoming:
			port, packetOut, valid := r.tryRoute(packetIn)
			if !valid {
				// warning message already printed
				continue
			}
			_ = port.WriteOutgoingPacket(packetOut)
		}
	}
}

// tryRoute attempts to route a raw packet.
func (r *Router) tryRoute(rawInput []byte) (*RouterPort, []byte, bool) {
	// parse the packet
	packet, err := DissectPacket(rawInput)
	if err != nil {
		r.logger.Warnf("netem: tryRoute: %s", err.Error())
		return nil, nil, false
	}

	// check whether we should drop this packet
	if ttl := packet.TimeToLive(); ttl <= 0 {
		r.logger.Warn("netem: tryRoute: TTL exceeded in transit")
		return nil, nil, false
	}
	packet.DecrementTimeToLive()

	// figure out the interface where to emit the packet
	destAddr := packet.DestinationIPAddress()
	r.mu.Lock()
	destPort := r.table[destAddr]
	r.mu.Unlock()
	if destPort == nil {
		log.Warnf("netem: tryRoute: %s: no route to host", destAddr)
		return nil, nil, false
	}

	// serialize a TCP or UDP packet while ignoring other protocols
	rawOutput, err := packet.Serialize()
	if err != nil {
		log.Warnf("netem: tryRoute: %s", err.Error())
		return nil, nil, false
	}

	return destPort, rawOutput, true
}
