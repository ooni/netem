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

// NDT0PerformanceSample is a performance sample returned by [RunNDT0Client].
type NDT0PerformanceSample struct {
	// ReceivedTotal is the total number of bytes received.
	ReceivedTotal int64

	// ReceivedLast is the total number of bytes received since
	// we collected the last sample.
	ReceivedLast int64

	// TimeLast is the last time we collected a sample.
	TimeLast time.Time

	// TimeNow is the time when we collected this sample.
	TimeNow time.Time

	// TimeZero is when the measurement started.
	TimeZero time.Time
}

// NDT0CSVHeader is the header for the CSV records returned
// by the [NDT0PerformanceSample.CSVRecord] function.
const NDT0CSVHeader = "elapsed (s),total (byte),current (byte),avg speed (Mbit/s),cur speed (Mbit/s)"

// ElapsedSeconds returns the elapsed time since the beginning
// of the measurement expressed in seconds.
func (ps *NDT0PerformanceSample) ElapsedSeconds() float64 {
	return ps.TimeNow.Sub(ps.TimeZero).Seconds()
}

// AvgSpeedMbps returns the average speed since the beginning
// of the measurement expressed in Mbit/s.
func (ps *NDT0PerformanceSample) AvgSpeedMbps() float64 {
	return (float64(ps.ReceivedTotal*8) / ps.ElapsedSeconds()) / (1000 * 1000)
}

// CSVRecord returns a CSV representation of the sample.
func (ps *NDT0PerformanceSample) CSVRecord() string {
	elapsedTotal := ps.ElapsedSeconds()
	avgSpeed := ps.AvgSpeedMbps()
	elapsedLast := ps.TimeNow.Sub(ps.TimeLast).Seconds()
	curSpeed := (float64(ps.ReceivedLast*8) / elapsedLast) / (1000 * 1000)
	return fmt.Sprintf(
		"%f,%d,%d,%f,%f",
		elapsedTotal,
		ps.ReceivedTotal,
		ps.ReceivedLast,
		avgSpeed,
		curSpeed,
	)
}

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
// - logger is the logger to use;
//
// - TLS controls whether we should use TLS;
//
// - errch is the channel where we emit the overall error;
//
// - perfch is the channel where we emit performance samples, which
// we close when we're done running.
func RunNDT0Client(
	ctx context.Context,
	stack NetUnderlyingNetwork,
	serverAddr string,
	logger Logger,
	TLS bool,
	errch chan<- error,
	perfch chan<- *NDT0PerformanceSample,
) {
	// as documented, close perfch when done using it
	defer close(perfch)

	// close errch when we leave the scope such that we return nil when
	// we don't explicitly return an error
	defer close(errch)

	// create ticker for periodically printing the download speed
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	// conditionally use TLS
	ns := &Net{stack}
	dialers := map[bool]func(context.Context, string, string) (net.Conn, error){
		false: ns.DialContext,
		true:  ns.DialTLSContext,
	}

	// connect to the server
	conn, err := dialers[TLS](ctx, "tcp", serverAddr)
	if err != nil {
		errch <- err
		return
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
	for {
		count, err := conn.Read(buffer)
		if err != nil {
			logger.Warnf("RunNDT0ClientNettest: %s", err.Error())
			return
		}
		current += int64(count)
		total += int64(count)

		select {
		case <-ticker.C:
			now := time.Now()
			perfch <- &NDT0PerformanceSample{
				ReceivedTotal: total,
				ReceivedLast:  current,
				TimeLast:      lastT,
				TimeNow:       now,
				TimeZero:      t0,
			}
			current = 0
			lastT = now

		case <-ctx.Done():
			return

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
// will post a nil value in case of success);
//
// - TLS controls whether we should use TLS.
func RunNDT0Server(
	ctx context.Context,
	stack NetUnderlyingNetwork,
	serverIPAddr net.IP,
	serverPort int,
	logger Logger,
	ready chan<- any,
	errorch chan<- error,
	TLS bool,
) {
	// create buffer with random data
	buffer := make([]byte, 65535)
	if _, err := rand.Read(buffer); err != nil {
		errorch <- err
		return
	}

	// conditionally use TLS
	ns := &Net{stack}
	listeners := map[bool]func(network string, addr *net.TCPAddr) (net.Listener, error){
		false: ns.ListenTCP,
		true:  ns.ListenTLS,
	}

	// listen for an incoming client connection
	addr := &net.TCPAddr{
		IP:   serverIPAddr,
		Port: serverPort,
		Zone: "",
	}
	listener, err := listeners[TLS]("tcp", addr)
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
