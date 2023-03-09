package netem

//
// Link frame forwarding: full implementation
//

import (
	"fmt"
	"time"
)

// LinkFwdFull is a full implementation of link forwarding that
// deals with delays, packet losses, and DPI.
//
// The kind of half-duplex link modeled by this function will
// look much more like a shared geographical link than an
// ethernet link. For example, this link allows out-of-order
// delivery of packets.
func LinkFwdFull(cfg *LinkFwdConfig) {

	//
	// 🚨 This algorithm is a bit complex. Be careful to check
	// you still preserve packet level properties after you have
	// modified it. In particular, we care about:
	//
	// - jitter scattering packets to mitigate bursts;
	//
	// - packet pacing at the TX, also to mitigate bursts;
	//
	// - out-of-order delivery both at the TX and at the RX
	// such that jitter actually works _and_ we can delay
	// specific flows using DPI;
	//
	// - drop-tail, small-buffer TX queue discipline;
	//
	// - tcptrace sequence graphs generated from cmd/calibrate
	// PCAPS should show that TCP sustains losses and enters
	// into fast recovery for moderate PLRs.
	//
	// See also [PERFORMANCE.md](PERFORMANCE.md).
	//

	// informative logging
	linkName := fmt.Sprintf(
		"linkFwdFull %s<->%s",
		cfg.Reader.InterfaceName(),
		cfg.Writer.InterfaceName(),
	)
	cfg.Logger.Debugf("netem: %s up", linkName)
	defer cfg.Logger.Debugf("netem: %s down", linkName)

	// synchronize with stop
	defer cfg.Wg.Done()

	// outgoing contains outgoing frames
	var outgoing []*Frame

	// accouting for queued bytes
	var queuedBytes int

	// inflight contains the frames currently in flight
	var inflight []*Frame

	// We assume that we can send 100 bit/µs (i.e., 100 Mbit/s). We also assume
	// that a packet is 1500 bytes (i.e., 12000 bits). The constant TX rate
	// is 120µs, and our code wakes up every 120µs to check for I/O.
	const bitsPerMicrosecond = 100
	const constantRate = 120 * time.Microsecond

	// We assume the TX buffer cannot hold more than this amount of bytes
	const maxQueuedBytes = 1 << 16

	// ticker to schedule I/O
	ticker := time.NewTicker(constantRate)
	defer ticker.Stop()

	// random number generator for jitter and PLR
	rng := cfg.newLinkgFwdRNG()

	for {
		select {
		case <-cfg.Reader.StackClosed():
			return

		// Userspace handler
		//
		// Whenever there is an IP packet, we enqueue it into a virtual
		// interface, account for the queuing delay, and moderate the queue
		// to avoid the most severe bufferbloat.
		case <-cfg.Reader.FrameAvailable():
			frame, err := cfg.Reader.ReadFrameNonblocking()
			if err != nil {
				cfg.Logger.Warnf("netem: ReadFrameNonblocking: %s", err.Error())
				continue
			}

			// drop incoming packet if the buffer is full
			if queuedBytes > maxQueuedBytes {
				continue
			}

			// avoid potential data races
			frame = frame.ShallowCopy()

			// create frame TX deadline accounting for time to send all the
			// previously queued frames in the outgoing buffer
			d := time.Now().Add(time.Duration(queuedBytes*8) / bitsPerMicrosecond)
			frame.Deadline = d

			// add to queue and wait for the TX to wakeup
			outgoing = append(outgoing, frame)
			queuedBytes += len(frame.Payload)

		// Ticker to emulate (slotted) sending and receiving over the channel
		case <-ticker.C:
			// wake up the transmitter first
			if len(outgoing) > 0 {
				// avoid head of line blocking that may be caused by adding jitter
				linkFwdSortFrameSliceInPlace(outgoing)

				// if the front frame is still pending, waste a cycle
				frame := outgoing[0]
				if d := time.Until(frame.Deadline); d > 0 {
					continue
				}

				// dequeue the first frame in the buffer
				queuedBytes -= len(frame.Payload)
				outgoing = outgoing[1:]

				// add random jitter to offset the effect of bursts
				jitter := time.Duration(rng.Int63n(1000)) * time.Microsecond

				// compute baseline frame PLR
				framePLR := cfg.PLR

				// allow the DPI to increase a flow's delay
				var flowDelay time.Duration

				// run the DPI engine, if configured
				policy, match := cfg.maybeInspectWithDPI(frame.Payload)
				if match {
					frame.Flags |= policy.Flags
					framePLR += policy.PLR
					flowDelay += policy.Delay
				}

				// check whether we need to drop this frame (we will drop it
				// at the RX so we simulate it being dropped in flight)
				if rng.Float64() < framePLR {
					frame.Flags |= FrameFlagDrop
				}

				// create frame RX deadline
				d := time.Now().Add(cfg.OneWayDelay + jitter + flowDelay)
				frame.Deadline = d

				// congratulations, the frame is now in flight 🚀
				inflight = append(inflight, frame)
			}

			// now wake up the receiver
			if len(inflight) > 0 {
				// avoid head of line blocking that may be caused by adding jitter
				linkFwdSortFrameSliceInPlace(inflight)

				// if the front frame is still pending, waste a cycle
				frame := inflight[0]
				if d := time.Until(frame.Deadline); d > 0 {
					continue
				}

				// the frame is no longer in flight
				inflight = inflight[1:]

				// don't leak the deadline to the destination NIC
				frame.Deadline = time.Time{}

				// deliver or drop the frame
				linkFwdDeliveryOrDrop(cfg.Writer, frame)
			}
		}
	}
}

// linkFwdDeliveryOrDrop delivers or drops a frame depending
// on the configured frame flags.
func linkFwdDeliveryOrDrop(writer WriteableNIC, frame *Frame) {
	if frame.Flags&FrameFlagDrop == 0 {
		_ = writer.WriteFrame(frame)
	}
}

var _ = LinkFwdFunc(LinkFwdFull)
