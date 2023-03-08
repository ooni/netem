package netem

//
// NIC related code
//

import (
	"fmt"
	"sync"
	"sync/atomic"
)

// nicID is the unique ID of each link NIC.
var nicID = &atomic.Int64{}

// newNICName constructs a new, unique name for a NIC.
func newNICName() string {
	return fmt.Sprintf("eth%d", nicID.Add(1))
}

// ReadableNIC is the read-only [NIC] used by frame forwarding algorithms.
type ReadableNIC interface {
	FrameReader
	InterfaceName() string
}

// WriteableNIC is the write-only [NIC] used by frame forwarding algorithms.
type WriteableNIC interface {
	InterfaceName() string
	WriteFrame(frame *Frame) error
}

// MocakbleNIC is a mockable [NIC] implementation.
type MockableNIC struct {
	// MockFrameAvailable allows mocking [NIC.FrameAvailable].
	MockFrameAvailable func() <-chan any

	// MockReadFrameNonblocking allows mocking [NIC.ReadFrameNonblocking].
	MockReadFrameNonblocking func() (*Frame, error)

	// MockStackClosed allows mocking [NIC.StackClosed].
	MockStackClosed func() <-chan any

	// MockClose allows mocking [NIC.Close].
	MockClose func() error

	// MockIPAddress allows mocking [NIC.IPAddress].
	MockIPAddress func() string

	// MockInterfaceName allows mocking [NIC.InterfaceName].
	MockInterfaceName func() string

	// MockWriteFrame allows mocking [NIC.WriteFrame].
	MockWriteFrame func(frame *Frame) error
}

var _ NIC = &MockableNIC{}

// FrameAvailable implements NIC
func (n *MockableNIC) FrameAvailable() <-chan any {
	return n.MockFrameAvailable()
}

// ReadFrameNonblocking implements NIC
func (n *MockableNIC) ReadFrameNonblocking() (*Frame, error) {
	return n.MockReadFrameNonblocking()
}

// StackClosed implements NIC
func (n *MockableNIC) StackClosed() <-chan any {
	return n.MockStackClosed()
}

// Close implements NIC
func (n *MockableNIC) Close() error {
	return n.MockClose()
}

// IPAddress implements NIC
func (n *MockableNIC) IPAddress() string {
	return n.MockIPAddress()
}

// InterfaceName implements NIC
func (n *MockableNIC) InterfaceName() string {
	return n.MockInterfaceName()
}

// WriteFrame implements NIC
func (n *MockableNIC) WriteFrame(frame *Frame) error {
	return n.MockWriteFrame(frame)
}

// StaticReadableNIC is a [ReadableNIC] that will return a fixed amount of
// frames. The zero value is invalid; use [NewStaticReadableNIC] factory to
// construct an instance. Remember to Close this NIC when you have read
// all the frames emitted by a channel to unblock the stack.
type StaticReadableNIC struct {
	// available implements FrameAvailable.
	available chan any

	// closeOnce ensures we close closes just once.
	closeOnce sync.Once

	// closed implements StackClosed.
	closed chan any

	// frames is the list of packets to return.
	frames []*Frame

	// mu protects frames.
	mu sync.Mutex

	// name is the interface name.
	name string
}

var _ ReadableNIC = &StaticReadableNIC{}

// NewStaticReadableNIC constructs a new [StaticReadableNIC] instance.
func NewStaticReadableNIC(name string, frames ...*Frame) *StaticReadableNIC {
	return &StaticReadableNIC{
		available: make(chan any, 1),
		closeOnce: sync.Once{},
		closed:    make(chan any),
		frames:    append([]*Frame{}, frames...),
		mu:        sync.Mutex{},
		name:      name,
	}
}

// FrameAvailable implements ReadableNIC
func (n *StaticReadableNIC) FrameAvailable() <-chan any {
	defer n.mu.Unlock()
	n.mu.Lock()
	if len(n.frames) > 0 {
		n.available <- true
	}
	return n.available
}

// ReadFrameNonblocking implements ReadableNIC
func (n *StaticReadableNIC) ReadFrameNonblocking() (*Frame, error) {
	defer n.mu.Unlock()
	n.mu.Lock()
	if len(n.frames) <= 0 {
		return nil, ErrNoPacket
	}
	frame := n.frames[0]
	n.frames = n.frames[1:]
	return frame, nil
}

// StackClosed implements ReadableNIC
func (n *StaticReadableNIC) StackClosed() <-chan any {
	defer n.mu.Unlock()
	n.mu.Lock()
	return n.closed
}

// InterfaceName implements ReadableNIC
func (n *StaticReadableNIC) InterfaceName() string {
	return n.name
}

// CloseNetworkStack closes the network stack used by this [NIC], which
// in turn causes StackClosed() to become readable.
func (n *StaticReadableNIC) CloseNetworkStack() {
	n.closeOnce.Do(func() {
		close(n.closed)
	})
}

// StaticWriteableNIC is a [WritableNIC] that collects all the
// frames it received for you to inspect later. The zero value
// is invalid; construct using [NewStaticWritableNIC].
type StaticWriteableNIC struct {
	// frames is where we post all the collected frames.
	frames chan *Frame

	// name is the interface name.
	name string
}

var _ WriteableNIC = &StaticWriteableNIC{}

// NewStaticWriteableNIC constructs a new [StaticWriteableNIC] instance.
func NewStaticWriteableNIC(name string) *StaticWriteableNIC {
	return &StaticWriteableNIC{
		frames: make(chan *Frame),
		name:   name,
	}
}

// InterfaceName implements WriteableNIC
func (n *StaticWriteableNIC) InterfaceName() string {
	return n.name
}

// WriteFrame implements WriteableNIC
func (n *StaticWriteableNIC) WriteFrame(frame *Frame) error {
	n.frames <- frame
	return nil
}

// Frames returns the channel where we post frames
func (n *StaticWriteableNIC) Frames() <-chan *Frame {
	return n.frames
}
