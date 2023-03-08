package netem_test

//
// Tests in this file may run for a long time and should verify
// that the overall/typical behavior is not broken.
//

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/apex/log"
	"github.com/google/go-cmp/cmp"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/montanaflynn/stats"
	"github.com/ooni/netem"
)

// TestLinkLatency ensures we can control a [Link]'s latency.
func TestLinkLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}

	t.Log("checking whether we can control a Link's latency")

	// require the [Link] to have ~200 ms of latency
	lc := &netem.LinkConfig{
		LeftToRightDelay: 100 * time.Millisecond,
		RightToLeftDelay: 100 * time.Millisecond,
	}

	// create a point-to-point topology, which consists of a single
	// [Link] connecting two userspace network stacks.
	topology, err := netem.NewPPPTopology(
		"10.0.0.2",
		"10.0.0.1",
		log.Log,
		lc,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer topology.Close()

	// connect N times and estimate the RTT by sending a SYN and measuring
	// the time required to get back the RST|ACK segment.
	var rtts []float64
	for idx := 0; idx < 10; idx++ {
		start := time.Now()
		conn, err := topology.Client.DialContext(context.Background(), "tcp", "10.0.0.1:443")
		rtts = append(rtts, time.Since(start).Seconds())

		// we expect to see ECONNREFUSED and a nil conn
		if !errors.Is(err, syscall.ECONNREFUSED) {
			t.Fatal(err)
		}
		if conn != nil {
			t.Fatal("expected nil conn")
		}
	}

	// make sure we have collected samples
	if len(rtts) < 1 {
		t.Fatal("expected at least one sample")
	}

	// we expect a median RTT which is larger than 200 ms
	median, err := stats.Median(rtts)
	if err != nil {
		t.Fatal(err)
	}
	const expectation = 0.2
	t.Log("median RTT", median, "expectation", expectation)
	if median < expectation {
		t.Fatal("median RTT is below expectation")
	}
}

// TestLinkPLR ensures we can control a [Link]'s PLR.
func TestLinkPLR(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}

	t.Log("checking whether we can increase a Link's PLR")

	// require the [Link] to have latency and losses
	lc := &netem.LinkConfig{
		LeftToRightDelay: 10 * time.Millisecond,
		RightToLeftDelay: 10 * time.Millisecond,
		RightToLeftPLR:   0.1,
	}

	// create a point-to-point topology, which consists of a single
	// [Link] connecting two userspace network stacks.
	topology, err := netem.NewPPPTopology(
		"10.0.0.2",
		"10.0.0.1",
		log.Log,
		lc,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer topology.Close()

	// make sure we have a deadline bound context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// start an NDT0 server in the background (NDT0 is a stripped down
	// NDT7 protocol that allows us to estimate network performance)
	ready, serverErrorCh := make(chan net.Listener, 1), make(chan error, 1)
	go netem.RunNDT0Server(
		ctx,
		topology.Server,
		net.ParseIP("10.0.0.1"),
		443,
		log.Log,
		ready,
		serverErrorCh,
		false,
	)

	// await for the NDT0 server to be listening
	listener := <-ready
	defer listener.Close()

	// run NDT0 client in the background and measure speed
	clientErrorCh := make(chan error, 1)
	perfch := make(chan *netem.NDT0PerformanceSample)
	go netem.RunNDT0Client(
		ctx,
		topology.Client,
		"10.0.0.1:443",
		log.Log,
		false,
		clientErrorCh,
		perfch,
	)

	// collect performance samples
	var avgSpeed float64
	for p := range perfch {
		if p.Final {
			avgSpeed = p.AvgSpeedMbps()
		}
	}

	// make sure we have a final average download speed
	if avgSpeed <= 0 {
		t.Fatal("did not collect the average speed")
	}

	// make sure that neither the client nor the server
	// reported a fundamental error
	if err := <-clientErrorCh; err != nil {
		t.Fatal(err)
	}
	if err := <-serverErrorCh; err != nil {
		t.Fatal(err)
	}

	// With MSS=1500, RTT=10 ms, PLR=0.1 (1%) we have seen speeds
	// around 1.8 - 2.4 Mbit/s. This occurred both in a development
	// machine and in a single processor cloud machine.
	//
	// We use the single processor cloud machine as a benchmark
	// for what to expect from GitHub actions. For reference, this
	// machine measured ~400 Mbit/s when the link configuration
	// was completely empty (meaning we used the fast link).
	//
	// These data inform our choices in terms of expectation in
	// this test as well as in other tests.
	const expectation = 10
	t.Log("measured goodput", avgSpeed, "expectation", expectation)
	if avgSpeed > expectation {
		t.Fatal("goodput above expectation")
	}
}

// TestRoutingWorksDNS verifies that routing is working for a simple
// network usage pattern such as using the DNS.
func TestRoutingWorksDNS(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}

	t.Logf("checking whether Router works for dnsping")

	// create a star topology, which consists of a single
	// [Router] connected to arbitrary hosts
	topology, err := netem.NewStarTopology(log.Log)
	if err != nil {
		t.Fatal(err)
	}
	defer topology.Close()

	// attach a client to the topology
	clientStack, err := topology.AddHost("10.0.0.2", "10.0.0.1", &netem.LinkConfig{})
	if err != nil {
		t.Fatal(err)
	}

	// attach a server to the topology
	serverStack, err := topology.AddHost("10.0.0.1", "10.0.0.1", &netem.LinkConfig{})
	if err != nil {
		t.Fatal(err)
	}

	// run a DNS server using the server stack
	dnsConfig := netem.NewDNSConfiguration()
	dnsConfig.AddRecord("example.local.", "example.xyz.", "10.0.0.1")
	dnsServer, err := netem.NewDNSServer(
		log.Log,
		serverStack,
		"10.0.0.1",
		dnsConfig,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer dnsServer.Close()

	// perform a bunch of DNS round trips
	const repetitions = 10
	for idx := 0; idx < repetitions; idx++ {
		query := netem.NewDNSRequestA("example.local")
		before := time.Now()
		resp, err := netem.DNSRoundTrip(context.Background(), clientStack, "10.0.0.1", query)
		elapsed := time.Since(before)
		if err != nil {
			t.Fatal(err)
		}
		addrs, cname, err := netem.DNSParseResponse(query, resp)
		if err != nil {
			t.Fatal(err)
		}
		if cname != "example.xyz." {
			t.Fatal("invalid CNAME", cname)
		}
		if diff := cmp.Diff([]string{"10.0.0.1"}, addrs); diff != "" {
			t.Fatal(diff)
		}
		t.Logf("got DNS response in %v", elapsed)
	}
}

// TestRoutingWorksHTTPS verifies that routing is working for a more
// complex network usage pattern such as using HTTPS.
func TestRoutingWorksHTTPS(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}

	t.Log("checking whether Router works for httpping")

	// create a star topology, which consists of a single
	// [Router] connected to arbitrary hosts
	topology, err := netem.NewStarTopology(log.Log)
	if err != nil {
		t.Fatal(err)
	}
	defer topology.Close()

	// attach a client to the topology
	clientStack, err := topology.AddHost("10.0.0.2", "10.0.0.1", &netem.LinkConfig{})
	if err != nil {
		t.Fatal(err)
	}

	// attach a server to the topology
	serverStack, err := topology.AddHost("10.0.0.1", "10.0.0.1", &netem.LinkConfig{})
	if err != nil {
		t.Fatal(err)
	}

	// run a DNS server using the server stack
	dnsConfig := netem.NewDNSConfiguration()
	dnsConfig.AddRecord("example.local.", "example.xyz.", "10.0.0.1")
	dnsServer, err := netem.NewDNSServer(
		log.Log,
		serverStack,
		"10.0.0.1",
		dnsConfig,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer dnsServer.Close()

	// run an HTTP/HTTPS/HTTP3 server using the server stack
	mux := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	go netem.HTTPListenAndServeAll(serverStack, mux)

	// TODO(bassosimone): sometimes this test is flaky

	// perform a bunch of HTTPS round trips
	const repetitions = 10
	for idx := 0; idx < repetitions; idx++ {
		req, err := http.NewRequest("GET", "https://example.local/", nil)
		if err != nil {
			t.Fatal(err)
		}
		txp := netem.NewHTTPTransport(clientStack)
		before := time.Now()
		resp, err := txp.RoundTrip(req)
		elapsed := time.Since(before)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			t.Fatal("unexpected status code", resp.StatusCode)
		}
		resp.Body.Close()
		t.Logf("got HTTPS response in %v", elapsed)
	}
}

// TestLinkPCAP ensures we can capture PCAPs.
func TestLinkPCAP(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}

	t.Log("checking whether we can capture a pcap file")

	// wrap the right NIC to capture PCAPs
	dirname, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dirname)
	filename := filepath.Join(dirname, "capture.pcap")
	lc := &netem.LinkConfig{
		RightNICWrapper: netem.NewPCAPDumper(filename, log.Log),
	}

	// create a point-to-point topology, which consists of a single
	// [Link] connecting two userspace network stacks.
	topology, err := netem.NewPPPTopology(
		"10.0.0.2",
		"10.0.0.1",
		log.Log,
		lc,
	)
	if err != nil {
		t.Fatal(err)
	}

	// connect N times and estimate the RTT by sending a SYN and measuring
	// the time required to get back the RST|ACK segment.
	for idx := 0; idx < 10; idx++ {
		conn, err := topology.Client.DialContext(context.Background(), "tcp", "10.0.0.1:443")
		// we expect to see ECONNREFUSED and a nil conn
		if !errors.Is(err, syscall.ECONNREFUSED) {
			t.Fatal(err)
		}
		if conn != nil {
			t.Fatal("expected nil conn")
		}
	}

	// explicitly close the topology to cause the PCAPDumper to stop.
	topology.Close()

	// TODO(bassosimone): this test is flaky

	// open the capture file
	filep, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer filep.Close()
	reader, err := pcapgo.NewReader(filep)
	if err != nil {
		t.Fatal(err)
	}

	// walk through the packets and count them
	var count int
	for {
		_, _, err := reader.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		count++
	}
	t.Log("captured", count, "packets")
	if count <= 0 {
		t.Fatal("we expected to capture at least one packet")
	}
}

// TestDPITCPThrottleForSNI verifies we can use the DPI to throttle
// connections using specific TLS SNIs.
func TestDPITCPThrottleForSNI(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}

	// testcase describes a test case
	type testcase struct {
		// name is the name of the test case
		name string

		// clientSNI is the SNI used by the client
		clientSNI string

		// offendingSNI is the SNI that would cause throttling
		offendingSNI string

		// checkAvgSpeed is a function the check whether
		// the speed is consistent with expectations
		checkAvgSpeed func(t *testing.T, speed float64)
	}

	var testcases = []testcase{{
		name:         "when the client is using a throttled SNI",
		clientSNI:    "ndt0.local",
		offendingSNI: "ndt0.local",
		checkAvgSpeed: func(t *testing.T, speed float64) {
			// See above comment regarding expected performance
			// under the given RTT, MSS, and PLR constraints
			const expectation = 5
			if speed > expectation {
				t.Fatal("goodput", speed, "above expectation", expectation)
			}
		},
	}, {
		name:         "when the client is not using a throttled SNI",
		clientSNI:    "ndt0.xyz",
		offendingSNI: "ndt0.local",
		checkAvgSpeed: func(t *testing.T, speed float64) {
			// See above comment regarding expected performance
			// under the given RTT, MSS, and PLR constraints
			const expectation = 5
			if speed < expectation {
				t.Fatal("goodput", speed, "below expectation", expectation)
			}
		},
	}}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Log("checking for TLS flow throttling", tc.name)

			// throttle the offending SNI to have high latency and hig losses
			dpiEngine := netem.NewDPIEngine(log.Log)
			dpiEngine.AddRule(&netem.DPIThrottleTrafficForTLSSNI{
				Logger: log.Log,
				PLR:    0.1,
				SNI:    tc.offendingSNI,
			})
			lc := &netem.LinkConfig{
				DPIEngine:        dpiEngine,
				LeftToRightDelay: 10 * time.Millisecond,
				RightToLeftDelay: 10 * time.Millisecond,
			}

			// create a point-to-point topology, which consists of a single
			// [Link] connecting two userspace network stacks.
			topology, err := netem.NewPPPTopology(
				"10.0.0.2",
				"10.0.0.1",
				log.Log,
				lc,
			)
			if err != nil {
				t.Fatal(err)
			}
			defer topology.Close()

			// make sure we have a deadline bound context
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			// add DNS server to resolve the clientSNI domain
			dnsConfig := netem.NewDNSConfiguration()
			dnsConfig.AddRecord(tc.clientSNI, "", "10.0.0.1")
			dnsServer, err := netem.NewDNSServer(log.Log, topology.Server, "10.0.0.1", dnsConfig)
			if err != nil {
				t.Fatal(err)
			}
			defer dnsServer.Close()

			// start an NDT0 server in the background
			ready, serverErrorCh := make(chan net.Listener, 1), make(chan error, 1)
			go netem.RunNDT0Server(
				ctx,
				topology.Server,
				net.ParseIP("10.0.0.1"),
				443,
				log.Log,
				ready,
				serverErrorCh,
				true,
			)

			// await for the NDT0 server to be listening
			listener := <-ready
			defer listener.Close()

			// run NDT0 client in the background and measure speed
			clientErrorCh := make(chan error, 1)
			perfch := make(chan *netem.NDT0PerformanceSample)
			go netem.RunNDT0Client(
				ctx,
				topology.Client,
				net.JoinHostPort(tc.clientSNI, "443"),
				log.Log,
				true,
				clientErrorCh,
				perfch,
			)

			// collect the average speed
			var avgSpeed float64
			for p := range perfch {
				if p.Final {
					avgSpeed = p.AvgSpeedMbps()
				}
			}

			// make sure we have collected samples
			if avgSpeed <= 0 {
				t.Fatal("did not collect the average speed")
			}

			// make sure that neither the client nor the server
			// reported a fundamental error
			if err := <-clientErrorCh; err != nil {
				t.Fatal(err)
			}
			if err := <-serverErrorCh; err != nil {
				t.Fatal(err)
			}

			t.Log("measured goodput", avgSpeed)

			// make sure that the speed is consistent with expectations
			tc.checkAvgSpeed(t, avgSpeed)
		})
	}
}

// TestDPITCPResetForSNI verifies we can use the DPI to reset TCP
// connections using specific TLS SNI values.
func TestDPITCPResetForSNI(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}

	// testcase describes a test case
	type testcase struct {
		// name is the name of the test case
		name string

		// clientSNI is the SNI used by the client
		clientSNI string

		// offendingSNI is the SNI that would cause throttling
		offendingSNI string

		// expectSamples indicates whether we expect to see samples
		expectSamples bool

		// expectServerErr is the server error we expect
		expectServerErr error

		// expectClientErr is the client error we expect
		expectClientErr error
	}

	var testcases = []testcase{{
		name:            "when the client is using a blocked SNI",
		clientSNI:       "ndt0.local",
		offendingSNI:    "ndt0.local",
		expectSamples:   false,
		expectServerErr: syscall.ECONNRESET, // the client RSTs the server
		expectClientErr: syscall.ECONNRESET, // caused by the injected segment
	}, {
		name:            "when the client is not using a blocked SNI",
		clientSNI:       "ndt0.xyz",
		offendingSNI:    "ndt0.local",
		expectSamples:   true,
		expectServerErr: nil,
		expectClientErr: nil,
	}}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Log("check for TLS flow RST", tc.name)

			// make sure that the offending SNI causes RST
			dpiEngine := netem.NewDPIEngine(log.Log)
			dpiEngine.AddRule(&netem.DPIResetTrafficForTLSSNI{
				Logger: log.Log,
				SNI:    tc.offendingSNI,
			})
			lc := &netem.LinkConfig{
				DPIEngine:        dpiEngine,
				LeftToRightDelay: 10 * time.Millisecond,
				RightToLeftDelay: 10 * time.Millisecond,
			}

			// Create a star topology. We MUST create such a topology because
			// the rule we're using REQUIRES a router in the path.
			topology, err := netem.NewStarTopology(log.Log)
			if err != nil {
				t.Fatal(err)
			}
			defer topology.Close()

			// create a client and a server stacks
			clientStack, err := topology.AddHost("10.0.0.2", "10.0.0.1", lc)
			if err != nil {
				t.Fatal(err)
			}
			serverStack, err := topology.AddHost("10.0.0.1", "10.0.0.1", &netem.LinkConfig{})
			if err != nil {
				t.Fatal(err)
			}

			// make sure we have a deadline bound context
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()

			// add DNS server to resolve the clientSNI domain
			dnsConfig := netem.NewDNSConfiguration()
			dnsConfig.AddRecord(tc.clientSNI, "", "10.0.0.1")
			dnsServer, err := netem.NewDNSServer(log.Log, serverStack, "10.0.0.1", dnsConfig)
			if err != nil {
				t.Fatal(err)
			}
			defer dnsServer.Close()

			// start an NDT0 server in the background
			ready, serverErrorCh := make(chan net.Listener, 1), make(chan error, 1)
			go netem.RunNDT0Server(
				ctx,
				serverStack,
				net.ParseIP("10.0.0.1"),
				443,
				log.Log,
				ready,
				serverErrorCh,
				true,
			)

			// await for the NDT0 server to be listening
			listener := <-ready
			defer listener.Close()

			// run NDT0 client in the background and measure speed
			clientErrorCh := make(chan error, 1)
			perfch := make(chan *netem.NDT0PerformanceSample)
			go netem.RunNDT0Client(
				ctx,
				clientStack,
				net.JoinHostPort(tc.clientSNI, "443"),
				log.Log,
				true,
				clientErrorCh,
				perfch,
			)

			// drain the performance channel
			var count int
			for range perfch {
				count++
			}

			t.Log("got", count, "samples with tc.expectSamples=", tc.expectSamples)

			// make sure we have seen samples if we expected samples
			if tc.expectSamples && count < 1 {
				t.Fatal("expected at least one sample")
			}

			// When we arrive here is means the client has exited but it may
			// be that the server is still stuck inside accept, which happens
			// when we drop SYN segments (which we could do in this test if
			// we set the .Drop flag of the DPI rule).
			//
			// So, we need to unblock the server, just in case, by explicitly
			// closing the listener. Otherwise, we'll block in the next
			// statement trying to read the server's overall error.
			listener.Close()

			// check the error reported by server
			err = <-serverErrorCh
			if !errors.Is(err, tc.expectServerErr) {
				t.Fatal("unexpected server error", err)
			}

			// check error reported by client
			err = <-clientErrorCh
			if !errors.Is(err, tc.expectClientErr) {
				t.Fatal("unexpected client error", err)
			}
		})
	}
}

// TestDPITCPDropForSNI verifies we can use the DPI to drop traffic
// for connections using specific TLS SNIs.
func TestDPITCPDropForSNI(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}

	// testcase describes a test case
	type testcase struct {
		// name is the name of the test case
		name string

		// clientSNI is the SNI used by the client
		clientSNI string

		// expectSamples indicates whether we expect to see samples
		expectSamples bool

		// offendingSNI is the SNI that would cause throttling
		offendingSNI string

		// expectServerErr is the server error we expect
		expectServerErr error

		// expectClientErr is the client error we expect
		expectClientErr error
	}

	var testcases = []testcase{{
		name:            "when the client is using a blocked SNI",
		clientSNI:       "ndt0.local",
		offendingSNI:    "ndt0.local",
		expectSamples:   false,
		expectServerErr: context.DeadlineExceeded,
		expectClientErr: context.DeadlineExceeded,
	}, {
		name:            "when the client is not using a blocked SNI",
		clientSNI:       "ndt0.xyz",
		offendingSNI:    "ndt0.local",
		expectSamples:   true,
		expectServerErr: nil,
		expectClientErr: nil,
	}}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Log("checking for SNI based traffic dropping", tc.name)

			// make sure that the offending SNI causes RST
			dpiEngine := netem.NewDPIEngine(log.Log)
			dpiEngine.AddRule(&netem.DPIDropTrafficForTLSSNI{
				Logger: log.Log,
				SNI:    tc.offendingSNI,
			})
			lc := &netem.LinkConfig{
				DPIEngine:        dpiEngine,
				LeftToRightDelay: 10 * time.Millisecond,
				RightToLeftDelay: 10 * time.Millisecond,
			}

			// create a point-to-point topology, which consists of a single
			// [Link] connecting two userspace network stacks.
			topology, err := netem.NewPPPTopology(
				"10.0.0.2",
				"10.0.0.1",
				log.Log,
				lc,
			)
			if err != nil {
				t.Fatal(err)
			}
			defer topology.Close()

			// make sure we have a deadline bound context
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()

			// add DNS server to resolve the clientSNI domain
			dnsConfig := netem.NewDNSConfiguration()
			dnsConfig.AddRecord(tc.clientSNI, "", "10.0.0.1")
			dnsServer, err := netem.NewDNSServer(log.Log, topology.Server, "10.0.0.1", dnsConfig)
			if err != nil {
				t.Fatal(err)
			}
			defer dnsServer.Close()

			// start an NDT0 server in the background
			ready, serverErrorCh := make(chan net.Listener, 1), make(chan error, 1)
			go netem.RunNDT0Server(
				ctx,
				topology.Server,
				net.ParseIP("10.0.0.1"),
				443,
				log.Log,
				ready,
				serverErrorCh,
				true,
			)

			// await for the NDT0 server to be listening
			listener := <-ready
			defer listener.Close()

			// run NDT0 client in the background and measure speed
			clientErrorCh := make(chan error, 1)
			perfch := make(chan *netem.NDT0PerformanceSample)
			go netem.RunNDT0Client(
				ctx,
				topology.Client,
				net.JoinHostPort(tc.clientSNI, "443"),
				log.Log,
				true,
				clientErrorCh,
				perfch,
			)

			// drain the performance channel
			var count int
			for range perfch {
				count++
			}

			t.Log("got", count, "samples with tc.expectSamples=", tc.expectSamples)

			// make sure we have seen samples if we expected samples
			if tc.expectSamples && count < 1 {
				t.Fatal("expected at least one sample")
			}

			// check the error reported by server
			err = <-serverErrorCh
			if !errors.Is(err, tc.expectServerErr) {
				t.Fatal("unexpected server error", err)
			}

			// check error reported by client
			err = <-clientErrorCh
			if !errors.Is(err, tc.expectClientErr) {
				t.Fatal("unexpected client error", err)
			}
		})
	}
}

// TestDPITCPDropForEndpoint verifies we can use the DPI to drop
// traffic for connections using specific endpoints.
func TestDPITCPDropForEndpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}

	// testcase describes a test case
	type testcase struct {
		// name is the name of the test case
		name string

		// usedEndpoint is the endpoint the client will connect to and
		// is also the endpoint where the server will listen
		usedEndpoint string

		// offendingEndpoint is the endpoint the DPI will try to block.
		offendingEndpoint string

		// expectSamples indicates whether we expect to see samples
		expectSamples bool

		// expectServerErr is the server error we expect
		expectServerErr error

		// expectClientErr is the client error we expect
		expectClientErr error
	}

	var testcases = []testcase{{
		name:              "when the client is using a blocked endpoint",
		usedEndpoint:      "10.0.0.1:443",
		offendingEndpoint: "10.0.0.1:443",
		expectSamples:     false,
		expectServerErr:   syscall.EINVAL,
		expectClientErr:   context.DeadlineExceeded,
	}, {
		name:              "when the client is not using a blocked endpoint",
		usedEndpoint:      "10.0.0.1:80",
		offendingEndpoint: "10.0.0.1:443",
		expectSamples:     true,
		expectServerErr:   nil,
		expectClientErr:   nil,
	}}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Log("checking for endpoint based blocking", tc.name)

			// parse server endpoint
			serverAddr, serverPort, err := net.SplitHostPort(tc.usedEndpoint)
			if err != nil {
				t.Fatal(err)
			}
			serverPortNum, err := strconv.Atoi(serverPort)
			if err != nil {
				t.Fatal(err)
			}

			// parse blocked endpoint
			blockedAddr, blockedPort, err := net.SplitHostPort(tc.offendingEndpoint)
			if err != nil {
				t.Fatal(err)
			}
			blockedPortNum, err := strconv.Atoi(blockedPort)
			if err != nil {
				t.Fatal(err)
			}

			// make sure that the offending SNI causes RST
			dpiEngine := netem.NewDPIEngine(log.Log)
			dpiEngine.AddRule(&netem.DPIDropTrafficForServerEndpoint{
				Logger:          log.Log,
				ServerIPAddress: blockedAddr,
				ServerPort:      uint16(blockedPortNum),
				ServerProtocol:  layers.IPProtocolTCP,
			})
			lc := &netem.LinkConfig{
				DPIEngine:        dpiEngine,
				LeftToRightDelay: 10 * time.Millisecond,
				RightToLeftDelay: 10 * time.Millisecond,
			}

			// create a point-to-point topology, which consists of a single
			// [Link] connecting two userspace network stacks.
			topology, err := netem.NewPPPTopology(
				"10.0.0.2",
				"10.0.0.1",
				log.Log,
				lc,
			)
			if err != nil {
				t.Fatal(err)
			}
			defer topology.Close()

			// make sure we have a deadline bound context
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()

			// start an NDT0 server in the background
			ready, serverErrorCh := make(chan net.Listener, 1), make(chan error, 1)
			go netem.RunNDT0Server(
				ctx,
				topology.Server,
				net.ParseIP(serverAddr),
				serverPortNum,
				log.Log,
				ready,
				serverErrorCh,
				false,
			)

			// await for the NDT0 server to be listening
			listener := <-ready
			defer listener.Close()

			// run NDT0 client in the background and measure speed
			clientErrorCh := make(chan error, 1)
			perfch := make(chan *netem.NDT0PerformanceSample)
			go netem.RunNDT0Client(
				ctx,
				topology.Client,
				tc.usedEndpoint,
				log.Log,
				false,
				clientErrorCh,
				perfch,
			)

			// drain the performance channel
			var count int
			for range perfch {
				count++
			}

			t.Log("got", count, "samples with tc.expectSamples=", tc.expectSamples)

			// make sure we have seen samples if we expected samples
			if tc.expectSamples && count < 1 {
				t.Fatal("expected at least one sample")
			}

			// When we arrive here is means the client has exited but it may
			// be that the server is still stuck inside accept, which happens
			// when we drop SYN segments (which we could do in this test).
			//
			// So, we need to unblock the server, just in case, by explicitly
			// closing the listener. Otherwise, we'll block in the next
			// statement trying to read the server's overall error.
			listener.Close()

			// check the error reported by server
			err = <-serverErrorCh
			if !errors.Is(err, tc.expectServerErr) {
				t.Fatal("unexpected server error", err)
			}

			// check error reported by client
			err = <-clientErrorCh
			if !errors.Is(err, tc.expectClientErr) {
				t.Fatal("unexpected client error", err)
			}
		})
	}
}
