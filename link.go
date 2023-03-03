package netem

//
// Network link modeling
//

import (
	"context"
	"math/rand"
	"sync"
	"time"
)

// LinkDirection is the direction of a link.
type LinkDirection int

// LinkDirectionLeftToRight is the left->right link direction.
const LinkDirectionLeftToRight = LinkDirection(0)

// LinkDirectionRightToLeft is the right->left link direction.
const LinkDirectionRightToLeft = LinkDirection(1)

// LinkConfig contains config for creating a [Link].
type LinkConfig struct {
	// LeftToRightPLR is the packet-loss rate in the left->right direction.
	LeftToRightPLR float64

	// LeftToRightDelay is the delay in the left->rigth direction.
	LeftToRightDelay time.Duration

	// RightToLeftDelay is the delay in the right->left direction.
	RightToLeftDelay time.Duration

	// RightToLeftPLR is the packet-loss rate in the right->left direction.
	RightToLeftPLR float64
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
type Link struct {
	// closeOnce allows Close to have a "once" semantics.
	closeOnce sync.Once

	// left is the left network stack.
	left NIC

	// right is the right network stack.
	right NIC

	// shutdown allows us to shutdown a link
	shutdown context.CancelFunc

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
	// create context for interrupting the [Link].
	ctx, cancel := context.WithCancel(context.Background())

	// create wait group to synchronize with [Link.Close]
	wg := &sync.WaitGroup{}

	// create link losses managers
	leftLLM := newLinkLossesManager(config.LeftToRightPLR)
	rightLLM := newLinkLossesManager(config.RightToLeftPLR)

	// forward traffic from left to right
	wg.Add(1)
	go linkForward(
		ctx,
		leftLLM,
		LinkDirectionLeftToRight,
		left,
		right,
		config.LeftToRightDelay,
		wg,
		logger,
	)

	// forward traffic from right to left
	wg.Add(1)
	go linkForward(
		ctx,
		rightLLM,
		LinkDirectionRightToLeft,
		right,
		left,
		config.RightToLeftDelay,
		wg,
		logger,
	)

	link := &Link{
		closeOnce: sync.Once{},
		left:      left,
		right:     right,
		shutdown:  cancel,
		wg:        wg,
	}
	return link
}

// Close closes the [Link].
func (lnk *Link) Close() error {
	lnk.closeOnce.Do(func() {
		lnk.left.Close()
		lnk.right.Close()
		lnk.shutdown()
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
	ctx context.Context,
	llm *linkLossesManager,
	direction LinkDirection,
	reader readableLinkNIC,
	writer writeableLinkNIC,
	oneWayDelay time.Duration,
	wg *sync.WaitGroup,
	logger Logger,
) {
	logger.Infof("netem: link %s %s up", reader.InterfaceName(), writer.InterfaceName())
	defer wg.Done()

	state := newLinkForwardingState()
	defer state.stop()

	for {
		select {
		case <-reader.StackClosed():
			logger.Infof("netem: link %s %s down", reader.InterfaceName(), writer.InterfaceName())
			return

		case <-reader.FrameAvailable():
			state.onFrameAvailable(reader, oneWayDelay, logger, llm)

		case <-state.shouldSend():
			state.onWriteDeadline(writer)
		}
	}
}

// linkForwardingState is the forwarding state of a link. The zero value
// is invalid, please construct using [newLinkForwardingState]. You
// MUST call the [linkForwardingState.stop] when done using this struct.
type linkForwardingState struct {
	frames []*Frame
	tckr   *time.Ticker
}

// defaultLinkTickerInterval is the default ticker interval we use.
const defaultLinkTickerInterval = 100 * time.Millisecond

// newLinkForwardingState creates a [linkForwardingState].
func newLinkForwardingState() *linkForwardingState {
	return &linkForwardingState{
		frames: []*Frame{},
		tckr:   time.NewTicker(defaultLinkTickerInterval),
	}
}

// stop stops the background goroutines used by [linkForwardingState]
func (lfs *linkForwardingState) stop() {
	lfs.tckr.Stop()
}

// onFrameAvailable should be called when a frame is available
func (lfs *linkForwardingState) onFrameAvailable(
	NIC readableLinkNIC,
	oneWayDelay time.Duration,
	logger Logger,
	llm *linkLossesManager,
) {
	// read frame from the reader NIC
	frame, err := NIC.ReadFrameNonblocking()
	if err != nil {
		logger.Warnf("netem: reader.ReadFrameNonblocking: %s", err.Error())
		return
	}

	// drop this frame if needed
	if llm.shouldDrop() {
		return
	}

	// adjust the original frame deadline to account for the one way delay
	frame.Deadline = frame.Deadline.Add(oneWayDelay)

	// congratulations, this frame is now in flight 🚀
	lfs.frames = append(lfs.frames, frame)

	// if this is the only frame in flight, adjust the next tick such
	// that the writer awakes just in time for this frame.
	if len(lfs.frames) == 1 {
		d := time.Until(frame.Deadline)
		if d <= 0 {
			d = time.Microsecond // note: Reset panics if passed a <= 0 value
		}
		lfs.tckr.Reset(d)
	}
}

// shouldSend returns a channel that is written every time a write deadline expires
func (lfs *linkForwardingState) shouldSend() <-chan time.Time {
	return lfs.tckr.C
}

// onWriteDeadline should be called when a write deadline expires.
func (lfs *linkForwardingState) onWriteDeadline(NIC writeableLinkNIC) {
	for {
		// if we have sent all the frames, return to a more conservative ticker
		// behavior that ensures we do not consume much CPU
		if len(lfs.frames) <= 0 {
			lfs.tckr.Reset(defaultLinkTickerInterval)
			break
		}

		// obtain a reference to the first frame
		frame := lfs.frames[0]

		// compute how much time in the future we should send this frame
		d := time.Until(frame.Deadline)

		// if the deadline is in the future, reset ticker accordingly
		if d > 0 {
			lfs.tckr.Reset(d)
			break
		}

		// otherwise this frame must be sent right now
		lfs.frames = lfs.frames[1:]
		_ = NIC.WriteFrame(frame)
	}
}

// linkLossesManager manages losses on the link. The zero value
// is invalid, use [newLinkLossesManager] to construct.
type linkLossesManager struct {
	// mu provides mutual exclusion
	mu sync.Mutex

	// rnd is the random number generator.
	rnd *rand.Rand

	// target is the target PLR.
	target float64
}

// newLinkLossesManager creates a new [linkLossesManager].
func newLinkLossesManager(targetPLR float64) *linkLossesManager {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	return &linkLossesManager{
		mu:     sync.Mutex{},
		rnd:    rnd,
		target: targetPLR,
	}
}

// shouldDrop returns true if this packet should be dropped.
func (llm *linkLossesManager) shouldDrop() bool {
	defer llm.mu.Unlock()
	llm.mu.Lock()
	return llm.rnd.Float64() < llm.target
}
