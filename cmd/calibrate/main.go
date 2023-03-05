// Command calibrate helps calibrating the implementation of [Link].
package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/apex/log"
	"github.com/bassosimone/netem"
)

func runCalibrationServer(ctx context.Context, stack netem.UnderlyingNetwork, ready chan any) {
	buffer := make([]byte, 65535)
	if _, err := rand.Read(buffer); err != nil {
		log.WithError(err).Fatal("rand.Read")
	}

	addr := &net.TCPAddr{
		IP:   net.IPv4(10, 0, 0, 1),
		Port: 443,
		Zone: "",
	}
	listener, err := stack.ListenTCP("tcp", addr)
	if err != nil {
		log.WithError(err).Fatal("server.ListenTCP")
	}
	close(ready)

	conn, err := listener.Accept()
	if err != nil {
		log.WithError(err).Fatal("listener.Accept")
	}
	listener.Close()

	if deadline, okay := ctx.Deadline(); okay {
		_ = conn.SetDeadline(deadline)
	}
	for {
		if _, err := conn.Write(buffer); err != nil {
			log.Warnf("runCalibrationServer: %s", err.Error())
			break
		}
	}
}

func runCalibrationClient(ctx context.Context, stack netem.UnderlyingNetwork) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	conn, err := stack.DialContext(ctx, "tcp", "10.0.0.1:443")
	if err != nil {
		log.WithError(err).Fatal("client.DialContext")
	}
	defer conn.Close()

	if deadline, okay := ctx.Deadline(); okay {
		_ = conn.SetDeadline(deadline)
	}

	buffer := make([]byte, 65535)

	var total int64
	t0 := time.Now()

	fmt.Printf("elapsed (s),total (byte),speed (Mbit/s)\n")
	for {
		count, err := conn.Read(buffer)
		if err != nil {
			log.Warnf("runCalibrationClient: %s", err.Error())
			return
		}
		total += int64(count)

		select {
		case <-ticker.C:
			elapsed := time.Since(t0).Seconds()
			speed := (float64(total*8) / elapsed) / (1000 * 1000)
			fmt.Printf("%f,%d,%f\n", elapsed, total, speed)
		case <-ctx.Done():
			return
		default:
			// nothing
		}
	}
}

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

	// start server in background and wait until it's listening
	serverReady := make(chan any)
	go runCalibrationServer(ctx, server, serverReady)
	<-serverReady

	// run client in foreground and measure speed
	go runCalibrationClient(ctx, client)

	<-ctx.Done()
}
