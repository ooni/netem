package netem

//
// Link frame forwarding: core implementation
//

import (
	"math/rand"
	"sort"
	"sync"
	"time"
)

// LinkFwdRNG is a [LinkFwdFunc] view of a [rand.Rand] abstracted for festability.
type LinkFwdRNG interface {
	// Float64 is like [rand.Rand.Float64].
	Float64() float64

	// Int63n is like [rand.Rand.Int63n].
	Int63n(n int64) int64
}

var _ LinkFwdRNG = &rand.Rand{}

// LinkFwdConfig contains config for frame forwarding algorithms. Make sure
// you initialize all the fields marked as MANDATORY.
type LinkFwdConfig struct {
	// DPIEngine is the OPTIONAL DPI engine.
	DPIEngine *DPIEngine

	// Logger is the MANDATORY logger.
	Logger Logger

	// NewLinkFwdRNG is an OPTIONAL factory that creates a new
	// random number generator, used for writing tests.
	NewLinkFwdRNG func() LinkFwdRNG

	// OneWayDelay is the OPTIONAL link one-way delay.
	OneWayDelay time.Duration

	// PLR is the OPTIONAL link packet-loss rate.
	PLR float64

	// Reader is the MANDATORY [NIC] from which to read frames.
	Reader ReadableNIC

	// Writer is the MANDATORY [NIC] where to write frames.
	Writer WriteableNIC

	// Wg is MANDATORY the wait group that the frame forwarding goroutine
	// will notify when it is shutting down.
	Wg *sync.WaitGroup
}

// LinkFwdFunc is type type of a link forwarding function.
type LinkFwdFunc func(cfg *LinkFwdConfig)

// newLinkFwdRNG creates a new [LinkFwdRNG]
func (cfg *LinkFwdConfig) newLinkgFwdRNG() LinkFwdRNG {
	if cfg.NewLinkFwdRNG != nil {
		return cfg.NewLinkFwdRNG()
	}
	return rand.New(rand.NewSource(time.Now().UnixNano()))
}

// maybeInspectWithDPI inspects a packet with DPI if configured.
func (cfg *LinkFwdConfig) maybeInspectWithDPI(payload []byte) (*DPIPolicy, bool) {
	if cfg.DPIEngine != nil {
		return cfg.DPIEngine.inspect(payload)
	}
	return nil, false
}

// linkFwdSortFrameSliceInPlace is a convenience function to sort
// a slice containing frames in place.
func linkFwdSortFrameSliceInPlace(frames []*Frame) {
	sort.SliceStable(frames, func(i, j int) bool {
		return frames[i].Deadline.Before(frames[j].Deadline)
	})
}

// linkForwardChooseBest forwards frames on the link. This function selects the right
// implementation depending on the provided configuration.
func linkForwardChooseBest(
	reader ReadableNIC,
	writer WriteableNIC,
	wg *sync.WaitGroup,
	logger Logger,
	dpiEngine *DPIEngine,
	plr float64,
	oneWayDelay time.Duration,
) {
	cfg := &LinkFwdConfig{
		DPIEngine:     dpiEngine,
		Logger:        logger,
		NewLinkFwdRNG: nil,
		OneWayDelay:   oneWayDelay,
		PLR:           plr,
		Reader:        reader,
		Writer:        writer,
		Wg:            wg,
	}
	if dpiEngine == nil && plr <= 0 && oneWayDelay <= 0 {
		LinkFwdFast(cfg)
		return
	}
	if dpiEngine == nil && plr <= 0 {
		LinkFwdWithDelay(cfg)
		return
	}
	LinkFwdFull(cfg)
}
