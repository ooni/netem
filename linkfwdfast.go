package netem

//
// Link frame forwarding: fast algorithm
//

import "fmt"

// LinkFwdFast is the fast implementation of frames forwarding. We select this
// implementation when there are no configured losses, delay, or DPI.
func LinkFwdFast(cfg *LinkFwdConfig) {
	// informative logging
	linkName := fmt.Sprintf(
		"linkFwdFast %s<->%s",
		cfg.Reader.InterfaceName(),
		cfg.Writer.InterfaceName(),
	)
	cfg.Logger.Infof("netem: %s up", linkName)
	defer cfg.Logger.Infof("netem: %s down", linkName)

	// synchronize with stop
	defer cfg.Wg.Done()

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
			_ = cfg.Writer.WriteFrame(frame)
		}
	}
}

var _ = LinkFwdFunc(LinkFwdFast)
