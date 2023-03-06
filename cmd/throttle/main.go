// Command throttle helps developing [DPIEngine].
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/apex/log"
	"github.com/bassosimone/netem"
	"github.com/bassosimone/netem/cmd/internal/optional"
	"github.com/bassosimone/netem/cmd/internal/topology"
)

func main() {
	// parse command line flags
	const sni = "ndt0.local"
	clientSNI := flag.String("client-sni", sni, "allows to change the client SNI")
	plr := flag.Float64("plr", 0, "PLR to add to packets")
	duration := flag.Duration("duration", 10*time.Second, "duration of the experiment")
	flag.Parse()

	// make sure we will eventually stop
	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()

	const (
		clientAddress = "10.0.0.2"
		serverAddress = "10.0.0.1"
	)

	// create DNS configuration
	dnsConfig := netem.NewDNSConfiguration()
	dnsConfig.AddRecord(*clientSNI, "", serverAddress)

	// create the DPI engine
	dpiEngine := &netem.DPIEngine{}
	dpiEngine.AddRule(&netem.DPIThrottleTrafficForTLSSNI{
		Logger: log.Log,
		PLR:    *plr,
		SNI:    sni,
	})

	// characteristics of the client link
	clientLink := &netem.LinkConfig{
		LeftNICWrapper:   nil,
		LeftToRightDelay: 20 * time.Millisecond,
		LeftToRightPLR:   1e-06,
		RightToLeftDelay: 20 * time.Millisecond,
		RightToLeftPLR:   1e-06,
		RightNICWrapper:  dpiEngine,
	}

	// create the required topology
	topology, clientStack, serverStack := topology.NewStar(
		clientAddress,
		clientLink,
		serverAddress,
		dnsConfig,
		optional.None[http.Handler](),
	)
	defer topology.Close()

	// start server in background
	ready, errch := make(chan any, 1), make(chan error, 1)
	go netem.RunNDT0Server(
		ctx,
		serverStack,
		net.ParseIP(serverAddress),
		54321,
		log.Log,
		ready,
		errch,
		true,
	)

	// wait for server to be listening
	<-ready

	// run client in foreground and measure speed
	clientErrch := make(chan error, 1)
	perfch := make(chan *netem.NDT0PerformanceSample)
	go netem.RunNDT0Client(
		ctx,
		clientStack,
		net.JoinHostPort(*clientSNI, "54321"),
		log.Log,
		true,
		clientErrch,
		perfch,
	)

	// loop and emit performance samples
	fmt.Printf("%s\n", netem.NDT0CSVHeader)
	for sample := range perfch {
		fmt.Printf("%s\n", sample.CSVRecord())
	}

	// obtain the error returned by the client
	errClient := <-clientErrch
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
