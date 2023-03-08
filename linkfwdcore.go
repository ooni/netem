package netem

//
// Link frame forwarding: core implementation
//

import (
	"sync"
	"time"
)

// LinkFwdConfig contains config for frame forwarding algorithms. Make sure
// you initialize all the fields marked as MANDATORY.
type LinkFwdConfig struct {
	// DPIEngine is the OPTIONAL DPI engine.
	DPIEngine *DPIEngine

	// Logger is the MANDATORY logger.
	Logger Logger

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
