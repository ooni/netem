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

	log.SetLevel(log.DebugLevel)

	// make sure we will eventually stop
	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()

	cfg, err := netem.NewTLSMITMConfig()
	if err != nil {
		log.WithError(err).Fatal("netem.NewTLSMITMConfig")
	}

	// create the client TCP/IP userspace stack
	client, err := netem.NewUNetStack(log.Log, uint32(*mtu), "10.0.0.2", cfg, "8.8.8.8")
	if err != nil {
		log.WithError(err).Fatal("netem.NewUNetStack")
	}
	defer client.Close()

	// create the server TCP/IP userspace stack
	server, err := netem.NewUNetStack(log.Log, uint32(*mtu), "10.0.0.1", cfg, "8.8.8.8")
	if err != nil {
		log.WithError(err).Fatal("netem.NewUNetStack")
	}
	defer server.Close()

	// connect the two stacks using a link
	linkConfig := &netem.LinkConfig{
		LeftNICWrapper:   nil,
		LeftToRightDelay: *rtt / 2,
		LeftToRightPLR:   0,
		RightToLeftDelay: *rtt / 2,
		RightToLeftPLR:   *plr,
		RightNICWrapper:  netem.NewPCAPDumper("calibration.pcap", log.Log),
	}
	link := netem.NewLink(log.Log, client, server, linkConfig)
	defer link.Close()

	// start server in background
	ready, errch := make(chan any, 1), make(chan error, 1)
	go netem.RunNDT0Server(ctx, server, net.IPv4(10, 0, 0, 1), 54321, log.Log, ready, errch)

	// wait for server to be listening
	<-ready

	// run client in foreground and measure speed
	netem.RunNDT0Client(ctx, client, "10.0.0.1:54321", log.Log)
}
