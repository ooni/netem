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
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	dnsConfig := netem.NewDNSConfig()
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
	dnsConfig := netem.NewDNSConfig()
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
	//
	// This test used to be flaky because it could be we listened after
	// the client tried to connect. To avoid this, listen in the test
	// goroutine and only run Serve in the background.
	mux := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	listener, err := serverStack.ListenTCP("tcp", &net.TCPAddr{
		IP:   net.ParseIP("10.0.0.1"),
		Port: 443,
		Zone: "",
	})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := &http.Server{
		TLSConfig: clientStack.ServerTLSConfig(),
		Handler:   mux,
	}
	go httpServer.ServeTLS(listener, "", "") // empty strings mean: use TLSConfig

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

	// perform an HTTPS roundtrip with the literal IP as target to get
	// confidence that we can safely use, e.g., https://8.8.8.8/
	req, err := http.NewRequest("GET", "https://10.0.0.1", nil)
	if err != nil {
		t.Fatal(err)
	}
	txp := netem.NewHTTPTransport(clientStack)
	before := time.Now()
	resp, err := txp.RoundTrip(req)
	elapsed := time.Since(before)
	if err != nil {
		t.Fatal("With literal IP:", err)
	}
	if resp.StatusCode != 200 {
		t.Fatal("With literal IP: unexpected status code", resp.StatusCode)
	}
	resp.Body.Close()
	t.Logf("With literal IP: got HTTPS response in %v", elapsed)
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
				Delay:  10 * time.Millisecond,
				Logger: log.Log,
				PLR:    0.1,
				SNI:    tc.offendingSNI,
			})
			lc := &netem.LinkConfig{
				DPIEngine:        dpiEngine,
				LeftToRightDelay: 100 * time.Microsecond,
				RightToLeftDelay: 100 * time.Microsecond,
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
			dnsConfig := netem.NewDNSConfig()
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

		// offendingSNI is the SNI that would cause blocking
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
			clientLinkConfig := &netem.LinkConfig{
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

			// make sure we add delay to the router<->server link because
			// the DPI rule we're testing relies on a race condition.
			serverLinkConfig := &netem.LinkConfig{
				LeftToRightDelay: 10 * time.Millisecond,
				RightToLeftDelay: 10 * time.Millisecond,
			}

			// create a client and a server stacks
			clientStack, err := topology.AddHost("10.0.0.2", "10.0.0.1", clientLinkConfig)
			if err != nil {
				t.Fatal(err)
			}
			serverStack, err := topology.AddHost("10.0.0.1", "10.0.0.1", serverLinkConfig)
			if err != nil {
				t.Fatal(err)
			}

			// make sure we have a deadline bound context
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()

			// add DNS server to resolve the clientSNI domain
			dnsConfig := netem.NewDNSConfig()
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

// TestDPITCPCloseConnectionForSNI verifies we can use the DPI to close
// connections using specific TLS SNI values.
func TestDPITCPCloseConnectionForSNI(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}

	// testcase describes a test case
	type testcase struct {
		// name is the name of the test case
		name string

		// clientSNI is the SNI used by the client
		clientSNI string

		// offendingSNI is the SNI that would cause blocking
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
		expectServerErr: io.EOF, // caused by the client seeing a FIN|ACK segment
		expectClientErr: io.EOF, // caused by the server reacting to the FIN|ACK segment
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
			t.Log("check for TLS flow FIN|ACK", tc.name)

			// make sure that the offending SNI causes EOF
			dpiEngine := netem.NewDPIEngine(log.Log)
			dpiEngine.AddRule(&netem.DPICloseConnectionForTLSSNI{
				Logger: log.Log,
				SNI:    tc.offendingSNI,
			})
			clientLinkConfig := &netem.LinkConfig{
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

			// make sure we add delay to the router<->server link because
			// the DPI rule we're testing relies on a race condition.
			serverLinkConfig := &netem.LinkConfig{
				LeftToRightDelay: 10 * time.Millisecond,
				RightToLeftDelay: 10 * time.Millisecond,
			}

			// create a client and a server stacks
			clientStack, err := topology.AddHost("10.0.0.2", "10.0.0.1", clientLinkConfig)
			if err != nil {
				t.Fatal(err)
			}
			serverStack, err := topology.AddHost("10.0.0.1", "10.0.0.1", serverLinkConfig)
			if err != nil {
				t.Fatal(err)
			}

			// make sure we have a deadline bound context
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()

			// add DNS server to resolve the clientSNI domain
			dnsConfig := netem.NewDNSConfig()
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

// TestDPITCPCloseConnectionForServerEndpoint verifies we can use the DPI to close
// connections using specific TCP server endpoint.
func TestDPITCPCloseConnectionForServerEndpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}

	// testcase describes a test case
	type testcase struct {
		// name is the name of the test case
		name string

		// offendingAddress is the address that would cause blocking; the server will
		// always use 10.0.0.1 as its IP address.
		offendingAddress string

		// expectSamples indicates whether we expect to see samples
		expectSamples bool

		// expectServerErr is the server error we expect
		expectServerErr error

		// expectClientErr is the client error we expect
		expectClientErr error
	}

	var testcases = []testcase{{
		name:             "when the client is using a blocked server",
		offendingAddress: "10.0.0.1",
		expectSamples:    false,
		expectServerErr:  syscall.EINVAL,       // unclear what causes this(?)
		expectClientErr:  syscall.ECONNREFUSED, // caused by the receipt of the RST|ACK
	}, {
		name:             "when the client is not using a blocked server",
		offendingAddress: "10.0.0.55",
		expectSamples:    true,
		expectServerErr:  nil,
		expectClientErr:  nil,
	}}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Log("check for TCP flow RST|ACK during connect", tc.name)

			// make sure that the offending address causes RST|ACK
			dpiEngine := netem.NewDPIEngine(log.Log)
			dpiEngine.AddRule(&netem.DPICloseConnectionForServerEndpoint{
				Logger:          log.Log,
				ServerIPAddress: tc.offendingAddress,
				ServerPort:      443,
			})
			clientLinkConfig := &netem.LinkConfig{
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

			// make sure we add delay to the router<->server link because
			// the DPI rule we're testing relies on a race condition.
			serverLinkConfig := &netem.LinkConfig{
				LeftToRightDelay: 10 * time.Millisecond,
				RightToLeftDelay: 10 * time.Millisecond,
			}

			// create a client and a server stacks
			clientStack, err := topology.AddHost("10.0.0.2", "10.0.0.1", clientLinkConfig)
			if err != nil {
				t.Fatal(err)
			}
			serverStack, err := topology.AddHost("10.0.0.1", "10.0.0.1", serverLinkConfig)
			if err != nil {
				t.Fatal(err)
			}

			// make sure we have a deadline bound context
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()

			// add DNS server to resolve the clientSNI domain
			dnsConfig := netem.NewDNSConfig()
			dnsConfig.AddRecord("ndt0.xyz", "", "10.0.0.1")
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
				net.JoinHostPort("ndt0.xyz", "443"),
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

// TestDPISpoofDNSResponse verifies we can use the DPI to spoof
// incoming DNS requests containing offending names.
func TestDPISpoofDNSResponse(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}

	// testcase describes a test case
	type testcase struct {
		// name is the name of the test case
		name string

		// usedDomain is the domain the client should query for
		usedDomain string

		// offendingDomain is the domain that would cause spoofing
		offendingDomain string

		// configuredAddrs contains the addresses we would
		// expect to see if there's no censorship.
		configuredAddrs map[string][]string

		// spoofedAddrs are the addresses we should spoof
		spoofedAddrs []string

		// expectAddrs are the addresses we expect to see
		expectAddrs []string
	}

	var testcases = []testcase{{
		name:            "when the client is querying for a blocked domain",
		usedDomain:      "dns.google",
		offendingDomain: "dns.quad9.net",
		configuredAddrs: map[string][]string{
			"dns.google":    {"8.8.8.8", "8.8.4.4"},
			"dns.quad9.net": {"149.112.112.112", "9.9.9.9"},
		},
		spoofedAddrs: []string{"10.10.34.34", "10.10.34.35"},
		expectAddrs:  []string{"8.8.8.8", "8.8.4.4"},
	}, {
		name:            "when the client is not querying for a blocked domain",
		usedDomain:      "dns.quad9.net",
		offendingDomain: "dns.quad9.net",
		configuredAddrs: map[string][]string{
			"dns.google":    {"8.8.8.8", "8.8.4.4"},
			"dns.quad9.net": {"149.112.112.112", "9.9.9.9"},
		},
		spoofedAddrs: []string{"10.10.34.34", "10.10.34.35"},
		expectAddrs:  []string{"10.10.34.34", "10.10.34.35"},
	}}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Log("check for DNS response spoof", tc.name)

			// make sure that the offending domain causes DNS spoofing
			dpiEngine := netem.NewDPIEngine(log.Log)
			dpiEngine.AddRule(&netem.DPISpoofDNSResponse{
				Addresses: tc.spoofedAddrs,
				Logger:    log.Log,
				Domain:    "dns.quad9.net",
			})
			clientLinkConfig := &netem.LinkConfig{
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

			// make sure we add delay to the router<->server link because
			// the DPI rule we're testing relies on a race condition.
			serverLinkConfig := &netem.LinkConfig{
				LeftToRightDelay: 10 * time.Millisecond,
				RightToLeftDelay: 10 * time.Millisecond,
			}

			// create a client and a server stacks
			clientStack, err := topology.AddHost("10.0.0.2", "10.0.0.1", clientLinkConfig)
			if err != nil {
				t.Fatal(err)
			}
			serverStack, err := topology.AddHost("10.0.0.1", "10.0.0.1", serverLinkConfig)
			if err != nil {
				t.Fatal(err)
			}

			// make sure we have a deadline bound context
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()

			// add DNS server to resolve the domains
			dnsConfig := netem.NewDNSConfig()
			for domain, addrs := range tc.configuredAddrs {
				dnsConfig.AddRecord(domain, "", addrs...)
			}
			dnsServer, err := netem.NewDNSServer(log.Log, serverStack, "10.0.0.1", dnsConfig)
			if err != nil {
				t.Fatal(err)
			}
			defer dnsServer.Close()

			// perform the DNS round trip
			clientNetStack := &netem.Net{clientStack}
			addrs, err := clientNetStack.LookupHost(ctx, tc.usedDomain)
			if err != nil {
				t.Fatal(err)
			}

			t.Log("got", addrs, "for", tc.usedDomain)

			// make sure the addrs are correct
			if diff := cmp.Diff(tc.expectAddrs, addrs); diff != "" {
				t.Fatal(diff)
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

		// expectClientErrCheck is the function that checks the resulting error
		expectClientErrChecker func(t *testing.T, err error)
	}

	var testcases = []testcase{{
		name:            "when the client is using a blocked SNI",
		clientSNI:       "ndt0.local",
		offendingSNI:    "ndt0.local",
		expectSamples:   false,
		expectServerErr: context.DeadlineExceeded,
		expectClientErrChecker: func(t *testing.T, err error) {
			if err == nil {
				t.Fatal("expected an error here")
			}
			if errors.Is(err, context.DeadlineExceeded) {
				return
			}
			if strings.HasSuffix(err.Error(), "i/o timeout") {
				return
			}
			t.Fatal("unexpected error", err.Error())
		},
	}, {
		name:            "when the client is not using a blocked SNI",
		clientSNI:       "ndt0.xyz",
		offendingSNI:    "ndt0.local",
		expectSamples:   true,
		expectServerErr: nil,
		expectClientErrChecker: func(t *testing.T, err error) {
			if err != nil {
				t.Fatal("unexpected error", err)
			}
		},
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
			dnsConfig := netem.NewDNSConfig()
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

			tc.expectClientErrChecker(t, <-clientErrorCh)
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

// TestDPITCPResetForString verifies we can use the DPI to reset
// traffic for connections containing specific strings.
func TestDPITCPResetForString(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}

	// testcase describes a test case
	type testcase struct {
		// name is the name of the test case
		name string

		// clientAddr is the client address to create and use
		clientAddr string

		// serverAddr is the server address to create and use
		serverAddr string

		// hostHeader is the host header to send
		hostHeader string

		// blockedAddr is the blocked server IP addr
		blockedAddr string

		// blockedString is the string that causes blocking
		blockedString string

		// expectClientErr is the client error we expect
		expectClientErr error
	}

	var testcases = []testcase{{
		name:            "when the filter should cause blocking",
		clientAddr:      "10.0.0.55",
		serverAddr:      "10.0.0.1",
		hostHeader:      "example.com",
		blockedAddr:     "10.0.0.1",
		blockedString:   "Host: example.com",
		expectClientErr: syscall.ECONNRESET,
	}, {
		name:            "when the server endpoint is correct but the string does not match",
		clientAddr:      "10.0.0.55",
		serverAddr:      "10.0.0.1",
		hostHeader:      "example.org",
		blockedAddr:     "10.0.0.1",
		blockedString:   "Host: example.com",
		expectClientErr: nil,
	}, {
		name:            "when the string matches but the server endpoint does not",
		clientAddr:      "10.0.0.55",
		serverAddr:      "10.0.0.44",
		hostHeader:      "example.com",
		blockedAddr:     "10.0.0.1",
		blockedString:   "Host: example.com",
		expectClientErr: nil,
	}}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Log("checking for string-based TCP reset", tc.name)

			// create server link
			serverLink := &netem.LinkConfig{
				LeftToRightDelay: 10 * time.Millisecond,
				RightToLeftDelay: 10 * time.Millisecond,
			}

			// make sure that the offending string causes RST
			dpiEngine := netem.NewDPIEngine(log.Log)
			dpiEngine.AddRule(&netem.DPIResetTrafficForString{
				Logger:          log.Log,
				ServerIPAddress: tc.blockedAddr,
				ServerPort:      80,
				String:          tc.blockedString,
			})

			// create client link
			clientLink := &netem.LinkConfig{
				DPIEngine:        dpiEngine,
				LeftToRightDelay: 10 * time.Millisecond,
				RightToLeftDelay: 10 * time.Millisecond,
			}

			// create a star topology, required because the router will send
			// back the spoofed traffic to us
			topology, err := netem.NewStarTopology(log.Log)
			if err != nil {
				t.Fatal(err)
			}
			defer topology.Close()

			// create server stack
			serverStack, err := topology.AddHost(tc.serverAddr, "8.8.8.8", serverLink)
			if err != nil {
				t.Fatal(err)
			}

			// create client stack
			clientStack, err := topology.AddHost(tc.clientAddr, "8.8.8.8", clientLink)
			if err != nil {
				t.Fatal(err)
			}

			// create HTTP listener for HTTP server
			serverIPAddr := net.ParseIP(tc.serverAddr)
			if serverIPAddr == nil {
				panic("tc.serverAddr is not a parseable IP address")
			}
			serverAddr := &net.TCPAddr{
				IP:   serverIPAddr,
				Port: 80,
				Zone: "",
			}
			serverListener, err := serverStack.ListenTCP("tcp", serverAddr)
			if err != nil {
				t.Fatal(err)
			}
			defer serverListener.Close()

			// start HTTP server
			httpServer := &http.Server{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if net.ParseIP(r.Host) != nil {
						panic("expected the r.Host to be a domain name")
					}
					w.Write([]byte("hello, world"))
				}),
			}
			go httpServer.Serve(serverListener)
			defer httpServer.Close()

			// create HTTP client transport
			clientTxp := netem.NewHTTPTransport(clientStack)

			// make sure we have a deadline bound context
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()

			// prepare the request to send
			URL := &url.URL{Scheme: "http", Host: tc.serverAddr, Path: "/"}
			req, err := http.NewRequestWithContext(ctx, "GET", URL.String(), nil)
			if err != nil {
				t.Fatal(err)
			}

			// make sure we include the correct host header instead of the one in the URL
			req.Host = tc.hostHeader

			// perform the HTTP round trip
			resp, err := clientTxp.RoundTrip(req)

			t.Log("round trip error:", err)

			// make sure the error is the expected one
			if !errors.Is(err, tc.expectClientErr) {
				t.Fatal("expected", tc.expectClientErr, "got", err)
			}

			// there's nothing else to do here in case of error
			if err != nil {
				return
			}

			t.Log("status code:", resp.StatusCode)

			// make sure the response status code is 200
			if resp.StatusCode != 200 {
				t.Fatal("expected 200 as the status code; got", resp.StatusCode)
			}
		})
	}
}
