// Command httpping measures the RTT using HTTP round trips.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/apex/log"
	"github.com/bassosimone/netem"
)

func main() {
	maxPings := flag.Int("count", 10, "number of HTTP pings to send")
	scheme := flag.String("scheme", "http", "URL scheme to use")
	flag.Parse()

	// create an empty star topology
	topology := netem.Must1(netem.NewStarTopology(log.Log))
	defer topology.Close()

	// add the client to the empty topology
	clientLink := &netem.LinkConfig{
		LeftNICWrapper:   netem.NewPCAPDumper("httpping.pcap", log.Log),
		LeftToRightDelay: 30 * time.Millisecond,
		LeftToRightPLR:   1e-06,
		RightToLeftDelay: 30 * time.Millisecond,
		RightToLeftPLR:   1e-06,
	}
	clientStack := netem.Must1(topology.AddHost("10.0.0.1", "1.1.1.1", clientLink))

	// add an HTTP server to the topology
	serverLink := &netem.LinkConfig{
		LeftToRightDelay: 1 * time.Millisecond,
		LeftToRightPLR:   1e-09,
		RightToLeftDelay: 1 * time.Millisecond,
		RightToLeftPLR:   1e-09,
	}
	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	netem.Must0(topology.AddHTTPServer("8.8.8.8", "1.1.1.1", serverLink, mux))

	// add a DNS server to the topology
	dnsConfig := netem.NewDNSConfiguration()
	netem.Must0(dnsConfig.AddRecord("dns.google", "", "8.8.8.8"))
	netem.Must0(topology.AddDNSServer("1.1.1.1", "1.1.1.1", serverLink, dnsConfig))

	// send HTTP pings and measure RTT
	targetURL := &url.URL{
		Scheme: *scheme,
		Host:   "dns.google",
		Path:   "/",
	}
	for idx := 0; idx < *maxPings; idx++ {
		singlePing(clientStack, targetURL.String())
	}
}

func singlePing(clientStack netem.HTTPUnderlyingNetwork, targetURL string) {
	txp := netem.NewHTTPTransport(clientStack)
	defer txp.CloseIdleConnections()

	fmt.Printf("> GET %s\n", targetURL)
	req := netem.Must1(http.NewRequest("GET", targetURL, nil))
	t0 := time.Now()
	resp, err := txp.RoundTrip(req)
	delta := time.Since(t0)

	if err != nil {
		fmt.Printf("< [rtt=%s] %s\n", delta, err.Error())
		time.Sleep(1 * time.Second)
		return
	}

	fmt.Printf("< [rtt=%s] %d %s\n", delta, resp.StatusCode, http.StatusText(resp.StatusCode))
	time.Sleep(1 * time.Second)
}
