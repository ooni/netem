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
	tlsFlag := flag.Bool("tls", false, "run NDT0 over TLS")
	duration := flag.Duration("duration", 10*time.Second, "duration of the calibration")
	flag.Parse()

	// make sure we will eventually stop
	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()

	// create a suitable DNS configuration
	dnsConfig := netem.NewDNSConfiguration()
	dnsConfig.AddRecord("ndt0.local", "", netem.PPPTopologyServerAddress.String())

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
		dnsConfig,
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
		*tlsFlag,
	)

	// wait for server to be listening
	<-ready

	// run client in foreground and measure speed
	errClient := netem.RunNDT0Client(
		ctx,
		topology.Client,
		net.JoinHostPort("ndt0.local", "54321"),
		log.Log,
		*tlsFlag,
	)
	if errClient != nil {
		log.Warnf("RunNDT0Client: %s", errClient.Error())
	}

	// obtain the error returned by the server
	errServer := <-errch
	if errServer != nil {
		log.Warnf("RunNDT0Server: %s", errClient.Error())
	}

	// explicitly close the topology to await for PCAPDumper to finish
	topology.Close()

	// panic if either of them failed
	netem.Must0(errClient)
	netem.Must0(errServer)
}
