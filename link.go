package netem

//
// Network link modeling
//

import (
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
	go linkForwardChooseBest(
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
	go linkForwardChooseBest(
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
