package netem

//
// Network diagnostic tool (NDT) v0.
//
// This version of the protocol does not actually exists but what
// we're doing here is conceptually similar to ndt7.
//

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"time"
)

// RunNDT0Client runs the NDT0 client nettest using the given server
// endpoint address and [UnderlyingNetwork].
//
// NDT0 is a stripped down NDT (network diagnostic tool) implementation
// where a client downloads from a server using a single stream.
//
// The version number is zero because we use the network like ndt7
// but we have much less implementation overhead.
//
// This function prints on the standard output download speed information
// every 250 milliseconds using the CSV data format.
//
// Arguments:
//
// - ctx limits the overall measurement runtime;
//
// - stack is the network stack to use;
//
// - serverAddr is the server endpoint address (e.g., 10.0.0.1:443);
//
// - logger is the logger to use.
func RunNDT0Client(
	ctx context.Context,
	stack UnderlyingNetwork,
	serverAddr string,
	logger Logger,
) error {
	// create ticker for periodically printing the download speed
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	// connect to the server
	conn, err := stack.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	// if the context has a deadline, apply it to the connection as well
	if deadline, okay := ctx.Deadline(); okay {
		_ = conn.SetDeadline(deadline)
	}

	// buffer for receiving from the server
	buffer := make([]byte, 65535)

	// current is the number of bytes read since the last tick
	var current int64

	// total is the number of bytes read thus far
	var total int64

	// t0 is when we started measuring
	t0 := time.Now()

	// lastT is the last time we sampled the connection
	lastT := time.Now()

	// run the measurement loop
	fmt.Printf("elapsed (s),total (byte),current (byte),avg speed (Mbit/s),cur speed (Mbit/s)\n")
	for {
		count, err := conn.Read(buffer)
		if err != nil {
			logger.Warnf("RunNDT0ClientNettest: %s", err.Error())
			return nil
		}
		current += int64(count)
		total += int64(count)

		select {
		case <-ticker.C:
			elapsed := time.Since(t0).Seconds()
			avgSpeed := (float64(total*8) / elapsed) / (1000 * 1000)
			curSpeed := (float64(current*8) / time.Since(lastT).Seconds()) / (1000 * 1000)
			fmt.Printf("%f,%d,%d,%f,%f\n", elapsed, total, current, avgSpeed, curSpeed)
			current = 0
			lastT = time.Now()
		case <-ctx.Done():
			return nil
		default:
			// nothing
		}
	}
}

// RunNDT0Server runs the NDT0 server. The server will listen for a single
// client connection and run until the client closes the connection.
//
// You should run this function in a background goroutine.
//
// Arguments:
//
// - ctx limits the overall measurement runtime;
//
// - stack is the network stack to use;
//
// - serverIPAddr is the IP address where we should listen;
//
// - serverPort is the TCP port where we should listen;
//
// - logger is the logger to use;
//
// - ready will be closed after we have started listening;
//
// - errorch is where we post the overall result of this function (we
// will post a nil value in case of success).
func RunNDT0Server(
	ctx context.Context,
	stack UnderlyingNetwork,
	serverIPAddr net.IP,
	serverPort int,
	logger Logger,
	ready chan<- any,
	errorch chan<- error,
) {
	// create buffer with random data
	buffer := make([]byte, 65535)
	if _, err := rand.Read(buffer); err != nil {
		errorch <- err
		return
	}

	// listen for an incoming client connection
	addr := &net.TCPAddr{
		IP:   serverIPAddr,
		Port: serverPort,
		Zone: "",
	}
	listener, err := stack.ListenTCP("tcp", addr)
	if err != nil {
		errorch <- err
		return
	}

	// notify the client it can now attempt connecting
	close(ready)

	// accept client connection and stop listening
	conn, err := listener.Accept()
	if err != nil {
		errorch <- err
		return
	}
	listener.Close()

	// if the context has a deadline, apply it to the connection as well
	if deadline, okay := ctx.Deadline(); okay {
		_ = conn.SetDeadline(deadline)
	}

	// run the measurement loop
	for {
		if _, err := conn.Write(buffer); err != nil {
			logger.Warnf("RunNDT0Server: %s", err.Error())
			errorch <- nil
			return
		}
	}
}
