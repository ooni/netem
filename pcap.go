package netem

//
// PCAP dumper
//

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// PCAPDumper collects a PCAP trace. The zero value is invalid and you should
// use [NewPCAPDumper] to instantiate. Once you have a valid instance, you
// should register the PCAPDumper as a [LinkNICWrapper] inside the [LinkConfig].
type PCAPDumper struct {
	// filename is the PCAP file name.
	filename string

	// logger is the logger to use.
	logger Logger
}

// NewPCAPDumper creates a new [PCAPDumper].
func NewPCAPDumper(filename string, logger Logger) *PCAPDumper {
	return &PCAPDumper{
		filename: filename,
		logger:   logger,
	}
}

var _ LinkNICWrapper = &PCAPDumper{}

// WrapNIC implements the [LinkNICWrapper] interface.
func (pd *PCAPDumper) WrapNIC(nic NIC) NIC {
	return newPCAPDumperNIC(pd.filename, nic, pd.logger)
}

// pcapDumperNIC is a [NIC] but also an open PCAP file. The zero
// value is invalid; use [newPCAPDumperNIC] to instantiate.
type pcapDumperNIC struct {
	// cancel stops the background goroutines.
	cancel context.CancelFunc

	// closeOnce provides "once" semantics for close.
	closeOnce sync.Once

	// logger is the logger to use.
	logger Logger

	// joined is closed when the background goroutine has terminated
	joined chan any

	// DPIStack is the wrapped NIC
	nic NIC

	// pich is the channel where we post packets to capture
	pich chan *pcapDumperPacketInfo
}

var _ NIC = &pcapDumperNIC{}

// pcapDumperPacketInfo contains info about a packet.
type pcapDumperPacketInfo struct {
	originalLength int
	snapshot       []byte
}

// newPCAPDumpernic wraps an existing [NIC], intercepts the packets read
// and written, and stores them into the given PCAP file. This function
// creates background goroutines for writing into the PCAP file. To
// join the goroutines, call [PCAPDumper.Close].
func newPCAPDumperNIC(filename string, nic NIC, logger Logger) *pcapDumperNIC {
	const manyPackets = 4096
	ctx, cancel := context.WithCancel(context.Background())
	pd := &pcapDumperNIC{
		cancel:    cancel,
		closeOnce: sync.Once{},
		joined:    make(chan any),
		logger:    logger,
		nic:       nic,
		pich:      make(chan *pcapDumperPacketInfo, manyPackets),
	}
	go pd.loop(ctx, filename)
	return pd
}

// FrameAvailable implements NIC
func (pd *pcapDumperNIC) FrameAvailable() <-chan any {
	return pd.nic.FrameAvailable()
}

// StackClosed implements NIC
func (pd *pcapDumperNIC) StackClosed() <-chan any {
	return pd.nic.StackClosed()
}

// IPAddress implements NIC
func (pd *pcapDumperNIC) IPAddress() string {
	return pd.nic.IPAddress()
}

// InterfaceName implements NIC
func (pd *pcapDumperNIC) InterfaceName() string {
	return pd.nic.InterfaceName()
}

// ReadFrameNonblocking implements NIC
func (pd *pcapDumperNIC) ReadFrameNonblocking() (*Frame, error) {
	// read the frame from the stack
	frame, err := pd.nic.ReadFrameNonblocking()
	if err != nil {
		return nil, err
	}

	// send packet information to the background writer
	pd.deliverPacketInfo(frame.Payload)

	// provide it to the caller
	return frame, nil
}

// deliverPacketInfo delivers packet info to the background writer.
func (pd *pcapDumperNIC) deliverPacketInfo(packet []byte) {
	// make sure the capture length makes sense
	packetLength := len(packet)
	captureLength := 256
	if packetLength < captureLength {
		captureLength = packetLength
	}

	// actually deliver the packet info
	pinfo := &pcapDumperPacketInfo{
		originalLength: len(packet),
		snapshot:       append([]byte{}, packet[:captureLength]...), // duplicate
	}
	select {
	case pd.pich <- pinfo:
	default:
		// just drop from the capture
	}
}

// loop is the loop that writes pcaps
func (pd *pcapDumperNIC) loop(ctx context.Context, filename string) {
	// synchronize with parent
	defer close(pd.joined)

	// open the file where to create the pcap
	filep, err := os.Create(filename)
	if err != nil {
		pd.logger.Warnf("netem: PCAPDumper: os.Create: %s", err.Error())
		return
	}
	defer func() {
		if err := filep.Close(); err != nil {
			pd.logger.Warnf("netem: PCAPDumper: filep.Close: %s", err.Error())
			// fallthrough
		}
	}()

	// write the PCAP header
	w := pcapgo.NewWriter(filep)
	const largeSnapLen = 262144
	if err := w.WriteFileHeader(largeSnapLen, layers.LinkTypeIPv4); err != nil {
		pd.logger.Warnf("netem: PCAPDumper: os.Create: %s", err.Error())
		return
	}

	// loop until we're done and write each entry
	for {
		select {
		case <-ctx.Done():
			return
		case pinfo := <-pd.pich:
			pd.doWritePCAPEntry(pinfo, w)
		}
	}
}

// doWritePCAPEntry writes the given packet entry into the PCAP file.
func (pd *pcapDumperNIC) doWritePCAPEntry(pinfo *pcapDumperPacketInfo, w *pcapgo.Writer) {
	ci := gopacket.CaptureInfo{
		Timestamp:      time.Now(),
		CaptureLength:  len(pinfo.snapshot),
		Length:         pinfo.originalLength,
		InterfaceIndex: 0,
		AncillaryData:  []interface{}{},
	}
	if err := w.WritePacket(ci, pinfo.snapshot); err != nil {
		pd.logger.Warnf("netem: w.WritePacket: %s", err.Error())
		// fallthrough
	}
}

// WriteFrame implements NIC
func (pd *pcapDumperNIC) WriteFrame(frame *Frame) error {
	// send packet information to the background writer
	pd.deliverPacketInfo(frame.Payload)

	// provide frame to the stack
	return pd.nic.WriteFrame(frame)
}

// Close implements NIC
func (pd *pcapDumperNIC) Close() error {
	pd.closeOnce.Do(func() {
		// notify the underlying stack to stop
		pd.nic.Close()

		// notify the background goroutine to terminate
		pd.cancel()

		// wait until the channel is drained
		pd.logger.Debugf("netem: PCAPDumper: awaiting for background writer to finish writing")
		<-pd.joined
	})
	return nil
}
