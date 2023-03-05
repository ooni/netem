// Command calibrate helps calibrating the implementation of [Link].
package main

import (
	"context"
	"flag"
	"net"
	"time"

	"github.com/apex/log"
	"github.com/bassosimone/netem"
)

func main() {
	// parse command line flags
	mtu := flag.Int("mtu", 1500, "MTU")
	plr := flag.Float64("plr", 0, "right-to-left packet loss rate")
	rtt := flag.Duration("rtt", 0, "RTT delay")
	duration := flag.Duration("duration", 10*time.Second, "duration of the calibration")
	flag.Parse()

	// make sure we will eventually stop
	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()

	// create a point-to-point topology
	topology := netem.Must1(netem.NewPPPTopology(
		log.Log,
		uint32(*mtu),
		&netem.LinkConfig{
			LeftNICWrapper:   nil,
			LeftToRightDelay: *rtt / 2,
			LeftToRightPLR:   0,
			RightToLeftDelay: *rtt / 2,
			RightToLeftPLR:   *plr,
			RightNICWrapper:  netem.NewPCAPDumper("calibration.pcap", log.Log),
		},
		netem.NewDNSConfiguration(),
	))
	defer topology.Close()

	// start server in background
	ready, errch := make(chan any, 1), make(chan error, 1)
	go netem.RunNDT0Server(
		ctx,
		topology.Server,
		netem.PPPTopologyServerAddress,
		54321,
		log.Log,
		ready,
		errch,
	)

	// wait for server to be listening
	<-ready

	// run client in foreground and measure speed
	netem.RunNDT0Client(
		ctx,
		topology.Client,
		net.JoinHostPort(netem.PPPTopologyServerAddress.String(), "54321"),
		log.Log,
	)
}
