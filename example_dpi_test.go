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

// This example shows how to use DPI to provoke an EOF when you see an offending string.
func Example_dpiCloseConnectionForString() {
	// Create a star topology for our hosts.
	topology, err := netem.NewStarTopology(&netem.NullLogger{})
	if err != nil {
		log.Fatal(err)
	}
	defer topology.Close()

	// Create DPI engine in the client link
	dpi := netem.NewDPIEngine(&netem.NullLogger{})

	// Add client stack to topology. Note that we don't need to
	// close the clientStack: the topology will do that.
	//
	// Note that we need to add delay because several DPI rules
	// rely on race conditions and delay helps.
	clientStack, err := topology.AddHost(
		"10.0.0.1", // host IP address
		"8.8.8.8",  // host DNS resolver IP address
		&netem.LinkConfig{
			LeftToRightDelay: time.Millisecond,
			RightToLeftDelay: time.Millisecond,
			DPIEngine:        dpi,
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	// Add DNS server stack to topology.
	dnsServerStack, err := topology.AddHost(
		"8.8.8.8",
		"8.8.8.8", // this host is its own DNS resolver
		&netem.LinkConfig{
			LeftToRightDelay: time.Millisecond,
			RightToLeftDelay: time.Millisecond,
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	// Add HTTPS server stack to topology.
	httpsServerStack, err := topology.AddHost(
		"5.4.3.21",
		"8.8.8.8",
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
	dnsConfig.AddRecord("www.example.com", "", "5.4.3.21")
	dnsConfig.AddRecord("example.com", "", "5.4.3.21")
	dnsServer, err := netem.NewDNSServer(
		&netem.NullLogger{},
		dnsServerStack,
		"8.8.8.8",
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
		IP:   net.ParseIP("5.4.3.21"),
		Port: 80,
	}
	httpsListener, err := httpsServerStack.ListenTCP("tcp", httpsAddr)
	if err != nil {
		log.Fatal(err)
	}
	httpsServer := &http.Server{
		Handler: mux,
	}
	go httpsServer.Serve(httpsListener)
	defer httpsServer.Close()

	// create an HTTP transport using the clientStack
	txp := netem.NewHTTPTransport(clientStack)

	// add DPI rule that closes the connection for the www.example.com string
	dpi.AddRule(&netem.DPICloseConnectionForString{
		Logger:          &netem.NullLogger{},
		ServerIPAddress: "5.4.3.21",
		ServerPort:      80,
		String:          "www.example.com",
	})

	// Note that all the code that follows is standard Go code that
	// would work for any implementation of http.RoundTripper.

	{
		// create HTTP request
		req, err := http.NewRequest("GET", "http://www.example.com/", nil)
		if err != nil {
			log.Fatal(err)
		}

		// perform HTTP round trip
		resp, err := txp.RoundTrip(req)
		fmt.Printf("%s %v\n", err.Error(), resp == nil)
	}

	{
		// create HTTP request
		req, err := http.NewRequest("GET", "http://example.com/", nil)
		if err != nil {
			log.Fatal(err)
		}

		// perform HTTP round trip
		resp, err := txp.RoundTrip(req)
		fmt.Printf("%v %v\n", err != nil, resp == nil)
		defer resp.Body.Close()
	}

	// Output:
	// EOF true
	// false false
	//
}

// This example shows how to use DPI to drop traffic after you see a given string,
func Example_dpiDropTrafficForString() {
	// Create a star topology for our hosts.
	topology, err := netem.NewStarTopology(&netem.NullLogger{})
	if err != nil {
		log.Fatal(err)
	}
	defer topology.Close()

	// Create DPI engine in the client link
	dpi := netem.NewDPIEngine(&netem.NullLogger{})

	// Add client stack to topology. Note that we don't need to
	// close the clientStack: the topology will do that.
	//
	// Note that we need to add delay because several DPI rules
	// rely on race conditions and delay helps.
	clientStack, err := topology.AddHost(
		"10.0.0.1", // host IP address
		"8.8.8.8",  // host DNS resolver IP address
		&netem.LinkConfig{
			LeftToRightDelay: time.Millisecond,
			RightToLeftDelay: time.Millisecond,
			DPIEngine:        dpi,
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	// Add DNS server stack to topology.
	dnsServerStack, err := topology.AddHost(
		"8.8.8.8",
		"8.8.8.8", // this host is its own DNS resolver
		&netem.LinkConfig{
			LeftToRightDelay: time.Millisecond,
			RightToLeftDelay: time.Millisecond,
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	// Add HTTPS server stack to topology.
	httpsServerStack, err := topology.AddHost(
		"5.4.3.21",
		"8.8.8.8",
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
	dnsConfig.AddRecord("www.example.com", "", "5.4.3.21")
	dnsConfig.AddRecord("example.com", "", "5.4.3.21")
	dnsServer, err := netem.NewDNSServer(
		&netem.NullLogger{},
		dnsServerStack,
		"8.8.8.8",
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
		IP:   net.ParseIP("5.4.3.21"),
		Port: 80,
	}
	httpsListener, err := httpsServerStack.ListenTCP("tcp", httpsAddr)
	if err != nil {
		log.Fatal(err)
	}
	httpsServer := &http.Server{
		Handler: mux,
	}
	go httpsServer.Serve(httpsListener)
	defer httpsServer.Close()

	// create an HTTP transport using the clientStack
	txp := netem.NewHTTPTransport(clientStack)

	// add DPI rule that drops traffic for the www.example.com string
	dpi.AddRule(&netem.DPIDropTrafficForString{
		Logger:          &netem.NullLogger{},
		ServerIPAddress: "5.4.3.21",
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
		fmt.Printf("%s - %v\n", err.Error(), resp == nil)
	}

	{
		// create HTTP request
		req, err := http.NewRequest("GET", "http://example.com/", nil)
		if err != nil {
			log.Fatal(err)
		}

		// perform HTTP round trip
		resp, err := txp.RoundTrip(req)
		fmt.Printf("%v - %v\n", err != nil, resp == nil)
		defer resp.Body.Close()
	}

	// Output:
	// context deadline exceeded - true
	// false - false
	//
}

// This example shows how to use DPI to spoof a blockpage for a string
func Example_dpiSpoofBlockpageForString() {
	// Create a star topology for our hosts.
	topology, err := netem.NewStarTopology(&netem.NullLogger{})
	if err != nil {
		log.Fatal(err)
	}
	defer topology.Close()

	// Create DPI engine in the client link
	dpi := netem.NewDPIEngine(&netem.NullLogger{})

	// Add client stack to topology. Note that we don't need to
	// close the clientStack: the topology will do that.
	//
	// Note that we need to add delay because several DPI rules
	// rely on race conditions and delay helps.
	clientStack, err := topology.AddHost(
		"10.0.0.1", // host IP address
		"8.8.8.8",  // host DNS resolver IP address
		&netem.LinkConfig{
			DPIEngine:        dpi,
			LeftToRightDelay: time.Millisecond,
			RightToLeftDelay: time.Millisecond,
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	// Add DNS server stack to topology.
	dnsServerStack, err := topology.AddHost(
		"8.8.8.8",
		"8.8.8.8", // this host is its own DNS resolver
		&netem.LinkConfig{
			LeftToRightDelay: time.Millisecond,
			RightToLeftDelay: time.Millisecond,
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	// Add HTTPS server stack to topology.
	httpsServerStack, err := topology.AddHost(
		"5.4.3.21",
		"8.8.8.8",
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
	dnsConfig.AddRecord("www.example.com", "", "5.4.3.21")
	dnsConfig.AddRecord("example.com", "", "5.4.3.21")
	dnsServer, err := netem.NewDNSServer(
		&netem.NullLogger{},
		dnsServerStack,
		"8.8.8.8",
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
		IP:   net.ParseIP("5.4.3.21"),
		Port: 80,
	}
	httpsListener, err := httpsServerStack.ListenTCP("tcp", httpsAddr)
	if err != nil {
		log.Fatal(err)
	}
	httpsServer := &http.Server{
		Handler: mux,
	}
	go httpsServer.Serve(httpsListener)
	defer httpsServer.Close()

	// create an HTTP transport using the clientStack
	txp := netem.NewHTTPTransport(clientStack)

	blockpage := []byte(`<html><head><title>451 Unavailable For Legal Reasons</title></head><body><center><h1>451 Unavailable For Legal Reasons</h1></center><p>This content is not available in your jurisdiction.</p></body></html>`)

	// add DPI rule that drops traffic for the www.example.com string
	dpi.AddRule(&netem.DPISpoofBlockpageForString{
		HTTPResponse:    netem.DPIFormatHTTPResponse(blockpage),
		Logger:          apexlog.Log,
		ServerIPAddress: "5.4.3.21",
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

	{
		// create HTTP request
		req, err := http.NewRequest("GET", "http://example.com/", nil)
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
	// <html><head><title>451 Unavailable For Legal Reasons</title></head><body><center><h1>451 Unavailable For Legal Reasons</h1></center><p>This content is not available in your jurisdiction.</p></body></html>
	// Bonsoir, Elliot!
	//
}
