package netem

//
// Network link modeling
//

import (
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
		config.DPIEngine,
		left,
		right,
		config.LeftToRightPLR,
		config.LeftToRightDelay,
		wg,
		logger,
	)

	// forward traffic from right to left
	wg.Add(1)
	go linkForward(
		config.DPIEngine,
		right,
		left,
		config.RightToLeftPLR,
		config.RightToLeftDelay,
		wg,
		logger,
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

// readableLinkNIC is a read-only [LinkNIC]
type readableLinkNIC interface {
	FrameReader
	InterfaceName() string
}

// writeableLinkNIC is a write-only [LinkNIC]
type writeableLinkNIC interface {
	InterfaceName() string
	WriteFrame(frame *Frame) error
}

// linkForward forwards frames on the link.
func linkForward(
	dpiEngine *DPIEngine,
	reader readableLinkNIC,
	writer writeableLinkNIC,
	plr float64,
	oneWayDelay time.Duration,
	wg *sync.WaitGroup,
	logger Logger,
) {
	logger.Infof("netem: link %s %s up", reader.InterfaceName(), writer.InterfaceName())

	// synchronize with stop
	defer wg.Done()

	// create queue containing frames to send
	var outgoing []*Frame

	// create queue containing frames in flight
	var inflight []*Frame

	// create ticker implementing the link speed
	lineClock := time.NewTicker(100 * time.Microsecond)
	defer lineClock.Stop()

	// create random number generator
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for {
		select {
		case <-reader.StackClosed():
			logger.Infof("netem: link %s %s down", reader.InterfaceName(), writer.InterfaceName())
			return

		case <-reader.FrameAvailable():
			// obtain frame from the userspace
			frame, err := reader.ReadFrameNonblocking()
			if err != nil {
				logger.Warnf("netem: ReadFrameNonblocking: %s", err.Error())
				continue
			}

			// shallow copy to allow for 100% safe mutation
			frame = frame.ShallowCopy()

			// check whether we should drop the frame
			framePLR := plr
			if dpiEngine != nil {
				policy, match := dpiEngine.inspect(frame.Payload)
				if match {
					frame.Flags |= policy.Flags
					framePLR += policy.PLR
				}
			}

			// check whether we have an upcoming drop event and
			// update the queue traversal size accordingly
			if rng.Float64() < framePLR {
				frame.Flags |= FrameFlagDrop
			}

			// We need jitter to ensure there is out of order delivery of
			// frames, which makes TCP non-sender limited.
			//
			// Here we MUTATE the frame.Deadline but this mutation is fine
			// because we performed a shallow copy.
			jitter := time.Duration(rng.Int63n(1000)) * time.Microsecond
			frame.Deadline = time.Now().Add(oneWayDelay + jitter)

			// now the frame is patiently waiting in the send queue
			outgoing = append(outgoing, frame)

		case <-lineClock.C:
			// check whether there is a frame to send
			if len(outgoing) > 0 {
				// dequeue and account for the one way delay
				frame := outgoing[0]
				outgoing = outgoing[1:]

				// congratulations, the frame is now in flight 🚀
				inflight = append(inflight, frame)
			}

			// check whether there is a frame to receive
			if len(inflight) > 0 {
				// allow out of order delivery by sorting frames by their deadline
				sort.SliceStable(inflight, func(i, j int) bool {
					return inflight[i].Deadline.Before(inflight[j].Deadline)
				})

				// send the first frame if it has an expired deadline
				frame := inflight[0]
				d := time.Until(frame.Deadline)
				if d <= 0 {
					// the frame is not inflight anymore
					inflight = inflight[1:]

					// deliver the frame unless it was dropped in flight
					if frame.Flags&FrameFlagDrop == 0 {
						_ = writer.WriteFrame(frame)
					}
				}
			}
		}
	}
}
