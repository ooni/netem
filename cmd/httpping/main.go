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
	"github.com/bassosimone/netem/cmd/internal/optional"
	"github.com/bassosimone/netem/cmd/internal/topology"
)

func main() {
	maxPings := flag.Int("count", 10, "number of HTTP pings to send")
	ppp := flag.Bool("ppp", false, "use a point-to-point topology without routers")
	scheme := flag.String("scheme", "http", "URL scheme to use")
	flag.Parse()

	// create the [http.Handler] we need
	mux := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	// define how the client link shoud look like
	clientLink := &netem.LinkConfig{
		LeftNICWrapper:   netem.NewPCAPDumper("httpping.pcap", log.Log),
		LeftToRightDelay: 30 * time.Millisecond,
		LeftToRightPLR:   1e-06,
		RightToLeftDelay: 30 * time.Millisecond,
		RightToLeftPLR:   1e-06,
	}

	// register the domain name we should be using
	dnsConfig := netem.NewDNSConfiguration()
	netem.Must0(dnsConfig.AddRecord("dns.google", "", "8.8.8.8"))

	// create the client and the topology
	topology, clientStack := topology.New(
		*ppp,
		"10.0.0.1",
		clientLink,
		"8.8.8.8",
		dnsConfig,
		optional.Some(mux),
	)
	defer topology.Close()

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

// singlePing sends a single ping and awaits for the response
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
