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

// PCAPDumper is a [NIC] but also an open PCAP file. The zero
// value is invalid; use [NewPCAPDumper] to instantiate.
type PCAPDumper struct {
	// cancel stops the background goroutines.
	cancel context.CancelFunc

	// closeOnce provides "once" semantics for close.
	closeOnce sync.Once

	// logger is the logger to use.
	logger Logger

	// joined is closed when the background goroutine has terminated
	joined chan any

	// pic is the channel where we post packets to capture
	pic chan *pcapDumperPacketInfo

	// DPIStack is the wrapped NIC
	nic NIC
}

var _ NIC = &PCAPDumper{}

// pcapDumperPacketInfo contains info about a packet.
type pcapDumperPacketInfo struct {
	originalLength int
	snapshot       []byte
}

// NewPCAPDumper wraps an existing [NIC], intercepts the packets read
// and written, and stores them into the given PCAP file. This function
// creates a background goroutine for writing into the PCAP file. To
// join the goroutine, call [PCAPDumper.Close].
func NewPCAPDumper(filename string, nic NIC, logger Logger) *PCAPDumper {
	const manyPackets = 4096
	ctx, cancel := context.WithCancel(context.Background())
	pd := &PCAPDumper{
		cancel:    cancel,
		closeOnce: sync.Once{},
		joined:    make(chan any),
		logger:    logger,
		pic:       make(chan *pcapDumperPacketInfo, manyPackets),
		nic:       nic,
	}
	go pd.loop(ctx, filename)
	return pd
}

// FrameAvailable implements NIC
func (pd *PCAPDumper) FrameAvailable() <-chan any {
	return pd.nic.FrameAvailable()
}

// StackClosed implements NIC
func (pd *PCAPDumper) StackClosed() <-chan any {
	return pd.nic.StackClosed()
}

// IPAddress implements NIC
func (pd *PCAPDumper) IPAddress() string {
	return pd.nic.IPAddress()
}

// InterfaceName implements NIC
func (pd *PCAPDumper) InterfaceName() string {
	return pd.nic.InterfaceName()
}

// ReadFrameNonblocking implements NIC
func (pd *PCAPDumper) ReadFrameNonblocking() (*Frame, error) {
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
func (pd *PCAPDumper) deliverPacketInfo(packet []byte) {
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
	case pd.pic <- pinfo:
	default:
		// just drop from the capture
	}
}

// loop is the loop that writes pcaps
func (pd *PCAPDumper) loop(ctx context.Context, filename string) {
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
		case pinfo := <-pd.pic:
			pd.doWritePCAPEntry(pinfo, w)
		}
	}
}

// doWritePCAPEntry writes the given packet entry into the PCAP file.
func (pd *PCAPDumper) doWritePCAPEntry(pinfo *pcapDumperPacketInfo, w *pcapgo.Writer) {
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
func (pd *PCAPDumper) WriteFrame(frame *Frame) error {
	// send packet information to the background writer
	pd.deliverPacketInfo(frame.Payload)

	// provide frame to the stack
	return pd.nic.WriteFrame(frame)
}

// Close implements NIC
func (pd *PCAPDumper) Close() error {
	pd.closeOnce.Do(func() {
		// notify the underlying stack to stop
		pd.nic.Close()

		// notify the background goroutine to terminate
		pd.cancel()

		// wait until the channel is drained
		pd.logger.Infof("netem: PCAPDumper: awaiting for background writer to finish writing")
		<-pd.joined
	})
	return nil
}
