// Command calibrate helps calibrating the implementation of [Link].
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"time"

	"github.com/apex/log"
	"github.com/ooni/netem"
)

func main() {
	// parse command line flags
	timedPrefix := "calibration_" + time.Now().Format("20060102T150405Z")
	pcapFilePrefix := flag.String("pcap-file-prefix", timedPrefix, "prefix of the PCAP files")
	plr := flag.Float64("plr", 0, "right-to-left packet loss rate")
	rtt := flag.Duration("rtt", 0, "RTT delay")
	star := flag.Bool("star", false, "force using a star network topology")
	tlsFlag := flag.Bool("tls", false, "run NDT0 over TLS")
	duration := flag.Duration("duration", 10*time.Second, "duration of the calibration")
	flag.Parse()

	// make sure we will eventually stop
	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()

	const (
		clientAddress = "10.0.0.2"
		serverAddress = "10.0.0.1"
	)

	// create DNS configuration
	dnsConfig := netem.NewDNSConfig()
	dnsConfig.AddRecord("ndt0.local", "", serverAddress)

	// characteristics of the client link
	clientLink := &netem.LinkConfig{
		DPIEngine:        nil,
		LeftNICWrapper:   netem.NewPCAPDumper(*pcapFilePrefix+"_client.pcap", log.Log),
		LeftToRightDelay: *rtt / 2,
		LeftToRightPLR:   0,
		RightNICWrapper:  netem.NewPCAPDumper(*pcapFilePrefix+"_server.pcap", log.Log),
		RightToLeftDelay: *rtt / 2,
		RightToLeftPLR:   *plr,
	}

	// create the required topology
	topology, clientStack, serverStack := newTopology(
		!*star,
		clientAddress,
		clientLink,
		serverAddress,
		dnsConfig,
	)
	defer topology.Close()

	// start server in background
	ready, serverErrch := make(chan net.Listener, 1), make(chan error, 1)
	go netem.RunNDT0Server(
		ctx,
		serverStack,
		net.ParseIP(serverAddress),
		54321,
		log.Log,
		ready,
		serverErrch,
		*tlsFlag,
	)

	// wait for server to be listening
	listener := <-ready

	// run client in the background and measure speed
	clientErrch := make(chan error, 1)
	perfch := make(chan *netem.NDT0PerformanceSample)
	go netem.RunNDT0Client(
		ctx,
		clientStack,
		"ndt0.local:54321",
		log.Log,
		*tlsFlag,
		clientErrch,
		perfch,
	)

	// loop and emit performance samples
	fmt.Printf("%s\n", netem.NDT0CSVHeader)
	for sample := range perfch {
		fmt.Printf("%s\n", sample.CSVRecord(*pcapFilePrefix, *rtt, *plr))
	}

	// obtain the error returned by the client
	errClient := <-clientErrch
	if errClient != nil {
		log.Warnf("RunNDT0Client: %s", errClient.Error())
	}

	// explicitly close the listener because it may be stuck
	listener.Close()

	// obtain the error returned by the server
	errServer := <-serverErrch
	if errServer != nil {
		log.Warnf("RunNDT0Server: %s", errClient.Error())
	}

	// explicitly close the topology to await for PCAPDumper to finish
	topology.Close()

	// panic if either of them failed
	netem.Must0(errClient)
	netem.Must0(errServer)
}
