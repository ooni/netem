package netem_test

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	apexlog "github.com/apex/log"
	"github.com/ooni/netem"
)

// This is a scenario where a www server modeling www.example.com communicates with
// itself, therefore, the DPI does not have any effect.
func Example_dpiDoesNotAffectLoopbackTraffic() {
	// Create a star topology for our hosts.
	topology, err := netem.NewStarTopology(&netem.NullLogger{})
	if err != nil {
		log.Fatal(err)
	}
	defer topology.Close()

	// Create DPI engine in the wwwStack link
	dpi := netem.NewDPIEngine(&netem.NullLogger{})

	// IP addresses used by this scenario
	const (
		wwwAddress      = "93.184.216.34"
		resolverAddress = "8.8.8.8"
	)

	// Add the WWW stack to topology. Note that we don't need to
	// close the stack: the topology will do that.
	//
	// Note that we need to add delay because several DPI rules
	// rely on race conditions and delay helps.
	wwwStack, err := topology.AddHost(
		wwwAddress,      // host IP address
		resolverAddress, // host DNS resolver IP address
		&netem.LinkConfig{
			DPIEngine:        dpi,
			LeftNICWrapper:   netem.NewPCAPDumper("client.pcap", &netem.NullLogger{}),
			LeftToRightDelay: time.Millisecond,
			RightToLeftDelay: time.Millisecond,
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	// Add DNS server stack to topology.
	dnsServerStack, err := topology.AddHost(
		resolverAddress,
		resolverAddress, // this host is its own DNS resolver
		&netem.LinkConfig{
			LeftToRightDelay: time.Millisecond,
			RightToLeftDelay: time.Millisecond,
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	// spawn a DNS server with the required configuration.
	dnsConfig := netem.NewDNSConfig()
	dnsConfig.AddRecord("www.example.com", "", wwwAddress)
	dnsServer, err := netem.NewDNSServer(
		&netem.NullLogger{},
		dnsServerStack,
		resolverAddress,
		dnsConfig,
	)
	if err != nil {
		log.Fatal(err)
	}
	defer dnsServer.Close()

	// spawn an HTTP server with the required configuration
	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Bonsoir, Elliot!"))
	})
	httpsAddr := &net.TCPAddr{
		IP:   net.ParseIP(wwwAddress),
		Port: 80,
	}
	httpsListener, err := wwwStack.ListenTCP("tcp", httpsAddr)
	if err != nil {
		log.Fatal(err)
	}
	httpsServer := &http.Server{
		Handler: mux,
	}
	go httpsServer.Serve(httpsListener)
	defer httpsServer.Close()

	// create an HTTP transport using the wwwStack
	//
	// This is crucial: it means the traffic is not going to exit the
	// loopback interface of stack, so DPI wouldn't see it
	txp := netem.NewHTTPTransport(wwwStack)

	blockpage := []byte(`<html><head><title>451 Unavailable For Legal Reasons</title></head><body><center><h1>451 Unavailable For Legal Reasons</h1></center><p>This content is not available in your jurisdiction.</p></body></html>`)

	// add DPI rule that drops traffic for the www.example.com string
	dpi.AddRule(&netem.DPISpoofBlockpageForString{
		HTTPResponse:    netem.DPIFormatHTTPResponse(blockpage),
		Logger:          apexlog.Log,
		ServerIPAddress: wwwAddress,
		ServerPort:      80,
		String:          "www.example.com",
	})

	// Note that all the code that follows is standard Go code that
	// would work for any implementation of http.RoundTripper.

	{
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		// create HTTP request
		req, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com/", nil)
		if err != nil {
			log.Fatal(err)
		}

		// perform HTTP round trip
		resp, err := txp.RoundTrip(req)
		if err != nil {
			log.Fatal(err)
		}
		defer resp.Body.Close()
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s\n", string(respBody))
	}

	// Output:
	// Bonsoir, Elliot!
	//
}
