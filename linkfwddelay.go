package netem

import (
	"fmt"
	"time"
)

// LinkFwdWithDelay is an implementation of link forwarding that only
// delays packets without losses and deep packet inspection.
func LinkFwdWithDelay(cfg *LinkFwdConfig) {
	// informative logging
	linkName := fmt.Sprintf(
		"linkFwdWithDelay %s<->%s",
		cfg.Reader.InterfaceName(),
		cfg.Writer.InterfaceName(),
	)
	cfg.Logger.Infof("netem: %s up", linkName)
	defer cfg.Logger.Infof("netem: %s down", linkName)

	// synchronize with stop
	defer cfg.Wg.Done()

	// inflight contains the frames currently in flight
	var inflight []*Frame

	// ticker to schedule sending frames
	const initialTimer = 100 * time.Millisecond
	ticker := time.NewTicker(initialTimer)
	defer ticker.Stop()

	for {
		select {
		case <-cfg.Reader.StackClosed():
			return

		case <-cfg.Reader.FrameAvailable():
			frame, err := cfg.Reader.ReadFrameNonblocking()
			if err != nil {
				cfg.Logger.Warnf("netem: ReadFrameNonblocking: %s", err.Error())
				continue
			}

			// avoid potential data races
			frame = frame.ShallowCopy()

			// create frame deadline
			d := time.Now().Add(cfg.OneWayDelay)
			frame.Deadline = d

			// register as inflight and possibly rearm timer
			inflight = append(inflight, frame)
			if len(inflight) == 1 {
				d := time.Until(frame.Deadline)
				if d <= 0 {
					d = time.Nanosecond // avoid panic
				}
				ticker.Reset(d)
			}

		case <-ticker.C:
			// avoid wasting CPU with a fast timer if there's nothing to do
			if len(inflight) <= 0 {
				ticker.Reset(initialTimer)
				continue
			}

			// if the front frame is still pending, rearm timer
			frame := inflight[0]
			d := time.Until(frame.Deadline)
			if d > 0 {
				ticker.Reset(d)
				continue
			}

			// avoid leaking the frame deadline to the caller
			frame.Deadline = time.Time{}

			// otherwise deliver the front frame
			inflight = inflight[1:]
			_ = cfg.Writer.WriteFrame(frame)

			// again, if the channel is empty, avoid wasting CPU
			if len(inflight) <= 0 {
				ticker.Reset(initialTimer)
				continue
			}

			// rearm timer for the next incoming frame
			frame = inflight[0]
			d = time.Until(frame.Deadline)
			if d <= 0 {
				d = time.Nanosecond // avoid panic
			}
			ticker.Reset(d)
		}
	}
}

var _ = LinkFwdFunc(LinkFwdWithDelay)
