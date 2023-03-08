package netem

//
// Network link modeling
//

import (
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"time"
)

// LinkNICWrapper allows wrapping [NIC]s used by a [Link] to
// log packets, collect PCAPs and implement DPI.
type LinkNICWrapper interface {
	WrapNIC(NIC) NIC
}

// LinkConfig contains config for creating a [Link].
type LinkConfig struct {
	// DPIEngine is the OPTIONAL [DPIEngine].
	DPIEngine *DPIEngine

	// LeftNICWrapper is the OPTIONAL [LinkNICWrapper] for the left NIC.
	LeftNICWrapper LinkNICWrapper

	// LeftToRightDelay is the OPTIONAL delay in the left->right direction.
	LeftToRightDelay time.Duration

	// LeftToRightPLR is the OPTIONAL packet-loss rate in the left->right direction.
	LeftToRightPLR float64

	// RightNICWrapper is the OPTIONAL [LinkNICWrapper] for the right NIC.
	RightNICWrapper LinkNICWrapper

	// RightToLeftDelay is the OPTIONAL delay in the right->left direction.
	RightToLeftDelay time.Duration

	// RightToLeftPLR is the OPTIONAL packet-loss rate in the right->left direction.
	RightToLeftPLR float64
}

// maybeWrapNICs wraps the NICs if the configuration says we should do that.
func (lc *LinkConfig) maybeWrapNICs(left, right NIC) (NIC, NIC) {
	if lc.LeftNICWrapper != nil {
		left = lc.LeftNICWrapper.WrapNIC(left)
	}
	if lc.RightNICWrapper != nil {
		right = lc.RightNICWrapper.WrapNIC(right)
	}
	return left, right
}

// Link models a link between a "left" and a "right" NIC. The zero value
// is invalid; please, use a constructor to create a new instance.
//
// A link is characterized by left-to-right and right-to-left delays, which
// are configured by the [Link] constructors. A link is also characterized
// by a left-to-right and right-to-left packet loss rate (PLR).
//
// Once you created a link, it will immediately start to forward traffic
// until you call [Link.Close] to shut it down.
//
// Because a [Link] MAY MUTATE incoming [Frame]s to adjust their deadline, you
// SHOULD NOT keep track (or mutate) [Frame]s emitted over a [Link].
type Link struct {
	// closeOnce allows Close to have a "once" semantics.
	closeOnce sync.Once

	// left is the left network stack.
	left NIC

	// right is the right network stack.
	right NIC

	// wg allows us to wait for the background goroutines
	wg *sync.WaitGroup
}

// NewLink creates a new [Link] instance and spawns goroutines for forwarding
// traffic between the left and the right [LinkNIC]. You MUST call [Link.Close] to
// stop these goroutines when you are done with the [Link].
//
// [NewLink] selects the fastest link implementation that satisfies the
// provided config. Emulating PLR, RTT, and DPI has a cost, and it doesn't
// make sense to pay such a cost if you don't need them.
//
// The returned [Link] TAKES OWNERSHIP of the left and right network stacks and
// ensures that their [Close] method is called when you call [Link.Close].
func NewLink(logger Logger, left, right NIC, config *LinkConfig) *Link {
	// create wait group to synchronize with [Link.Close]
	wg := &sync.WaitGroup{}

	// possibly wrap the NICs
	left, right = config.maybeWrapNICs(left, right)

	// forward traffic from left to right
	wg.Add(1)
	go linkForward(
		left,
		right,
		wg,
		logger,
		config.DPIEngine,
		config.LeftToRightPLR,
		config.LeftToRightDelay,
	)

	// forward traffic from right to left
	wg.Add(1)
	go linkForward(
		right,
		left,
		wg,
		logger,
		config.DPIEngine,
		config.RightToLeftPLR,
		config.RightToLeftDelay,
	)

	link := &Link{
		closeOnce: sync.Once{},
		left:      left,
		right:     right,
		wg:        wg,
	}
	return link
}

// Close closes the [Link].
func (lnk *Link) Close() error {
	lnk.closeOnce.Do(func() {
		lnk.left.Close()
		lnk.right.Close()
		lnk.wg.Wait()
	})
	return nil
}

// linkForward forwads frames on the link. This function selects the right
// implementation depending on the provided configuration.
func linkForward(
	reader ReadableNIC,
	writer WriteableNIC,
	wg *sync.WaitGroup,
	logger Logger,
	dpiEngine *DPIEngine,
	plr float64,
	oneWayDelay time.Duration,
) {
	cfg := &LinkFwdConfig{
		DPIEngine:   dpiEngine,
		Logger:      logger,
		OneWayDelay: oneWayDelay,
		PLR:         plr,
		Reader:      reader,
		Writer:      writer,
		Wg:          wg,
	}
	if dpiEngine == nil && plr <= 0 && oneWayDelay <= 0 {
		LinkFwdFast(cfg)
		return
	}
	if dpiEngine == nil && plr <= 0 {
		LinkFwdWithDelay(cfg)
		return
	}
	linkForwardFull(reader, writer, wg, logger, dpiEngine, plr, oneWayDelay)
}

// linkForwardFull is a full implementation of link forwarding that deals
// with delays, packet losses, and DPI.
func linkForwardFull(
	reader ReadableNIC,
	writer WriteableNIC,
	wg *sync.WaitGroup,
	logger Logger,
	dpiEngine *DPIEngine,
	plr float64,
	oneWayDelay time.Duration,
) {
	// informative logging
	linkName := fmt.Sprintf("linkForwardFull %s<->%s", reader.InterfaceName(), writer.InterfaceName())
	logger.Infof("netem: %s up", linkName)
	defer logger.Infof("netem: %s down", linkName)

	// synchronize with stop
	defer wg.Done()

	// outgoing contains outgoing frames
	var outgoing []*Frame

	// accouting for queued bytes
	var queuedBytes int

	// inflight contains the frames currently in flight
	var inflight []*Frame

	// We assume that we can send 100 bit/µs (i.e., 100 Mbit/s). We also
	// that a packet is 1500 bytes (i.e., 12000 bits). The constant TX rate
	// is 120µs and our code waks up every 120µs to check for I/O.
	const bitsPerMicrosecond = 100
	const constantRate = 120 * time.Microsecond

	// We assume the TX buffer cannot hold more than this amount of bytes
	const maxQueuedBytes = 1 << 16

	// ticker to schedule I/O
	ticker := time.NewTicker(constantRate)
	defer ticker.Stop()

	// random number generator for jitter and PLR
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for {
		select {
		case <-reader.StackClosed():
			return

		// Userspace handler
		//
		// Whenever there is an IP packet, we enqueue it into a virtual
		// interface, account for the queuing delay, and moderate the queue
		// to avoid the most severe bufferbloat.
		case <-reader.FrameAvailable():
			frame, err := reader.ReadFrameNonblocking()
			if err != nil {
				logger.Warnf("netem: ReadFrameNonblocking: %s", err.Error())
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
				sort.SliceStable(outgoing, func(i, j int) bool {
					return outgoing[i].Deadline.Before(outgoing[j].Deadline)
				})

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
				framePLR := plr

				// run the DPI engine
				if dpiEngine != nil {
					policy, match := dpiEngine.inspect(frame.Payload)
					if match {
						frame.Flags |= policy.Flags
						framePLR += policy.PLR
					}
				}

				// check whether we need to drop this frame
				if rng.Float64() < framePLR {
					frame.Flags |= FrameFlagDrop
				}

				// create frame RX deadline
				d := time.Now().Add(oneWayDelay + jitter)
				frame.Deadline = d

				// congratulations, the frame is now in flight 🚀
				inflight = append(inflight, frame)
			}

			// now wake up the receiver
			if len(inflight) > 0 {
				// avoid head of line blocking that may be caused by adding jitter
				sort.SliceStable(inflight, func(i, j int) bool {
					return inflight[i].Deadline.Before(inflight[j].Deadline)
				})

				// if the front frame is still pending, waste a cycle
				frame := inflight[0]
				if d := time.Until(frame.Deadline); d > 0 {
					continue
				}

				// the frame is no longer in flight
				inflight = inflight[1:]

				// deliver it unless we need to drop it
				if frame.Flags&FrameFlagDrop == 0 {
					_ = writer.WriteFrame(frame)
				}
			}
		}
	}
}
