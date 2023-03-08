package netem_test

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"

	"github.com/ooni/netem"
)

// This example shows how to create a star topology, a DNS server, and
// an HTTPS server. Then we create an HTTPS client and we use such a
// client to fetch a very important message from the server.
func Example_starTopologyHTTPSAndDNS() {
	// Create a star topology for our hosts.
	topology, err := netem.NewStarTopology(&netem.NullLogger{})
	if err != nil {
		log.Fatal(err)
	}
	defer topology.Close()

	// Add client stack to topology. Note that we don't need to
	// close the clientStack: the topology will do that.
	clientStack, err := topology.AddHost(
		"10.0.0.1",          // host IP address
		"8.8.8.8",           // host DNS resolver IP address
		&netem.LinkConfig{}, // link with no PLR, RTT, DPI
	)
	if err != nil {
		log.Fatal(err)
	}

	// Add DNS server stack to topology.
	dnsServerStack, err := topology.AddHost(
		"8.8.8.8",
		"8.8.8.8", // this host is its own DNS resolver
		&netem.LinkConfig{},
	)
	if err != nil {
		log.Fatal(err)
	}

	// Add HTTPS server stack to topology.
	httpsServerStack, err := topology.AddHost(
		"5.4.3.21",
		"8.8.8.8",
		&netem.LinkConfig{},
	)
	if err != nil {
		log.Fatal(err)
	}

	// spawn a DNS server with the required configuration.
	dnsConfig := netem.NewDNSConfig()
	dnsConfig.AddRecord("tyrell.wellick.name", "tw01.fsociety.com.", "5.4.3.21")
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
		Port: 443,
	}
	httpsListener, err := httpsServerStack.ListenTCP("tcp", httpsAddr)
	if err != nil {
		log.Fatal(err)
	}
	httpsServer := &http.Server{
		Handler:   mux,
		TLSConfig: httpsServerStack.ServerTLSConfig(), // allow for TLS MITM
	}
	go httpsServer.ServeTLS(httpsListener, "", "") // empty string: use .TLSConfig
	defer httpsServer.Close()

	// create an HTTP transport using the clientStack
	txp := netem.NewHTTPTransport(clientStack)

	// Note that all the code that follows is standard Go code that
	// would work for any implementation of http.RoundTripper.

	// create HTTP request
	req, err := http.NewRequest("GET", "https://tyrell.wellick.name/", nil)
	if err != nil {
		log.Fatal(err)
	}

	// perform HTTP round trip
	resp, err := txp.RoundTrip(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	// read the response body
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%d\n", resp.StatusCode)
	fmt.Printf("%s\n", string(data))
	// Output:
	// 200
	// Bonsoir, Elliot!
	//
}
