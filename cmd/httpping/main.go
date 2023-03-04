// Command httpping measures the RTT using HTTP round trips.
package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/apex/log"
	"github.com/bassosimone/netem"
)

func main() {
	topology := netem.Must1(netem.NewTopology(log.Log))
	defer topology.Close()

	slowLink := &netem.LinkConfig{
		LeftToRightDelay: 30 * time.Millisecond,
		LeftToRightPLR:   1e-06,
		RightToLeftDelay: 30 * time.Millisecond,
		RightToLeftPLR:   1e-06,
	}

	clientStack := netem.Must1(topology.AddHost("10.0.0.1", "1.1.1.1", slowLink))

	fastLink := &netem.LinkConfig{
		LeftToRightDelay: 1 * time.Millisecond,
		LeftToRightPLR:   1e-09,
		RightToLeftDelay: 1 * time.Millisecond,
		RightToLeftPLR:   1e-09,
	}

	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	netem.Must0(topology.AddHTTPServer("8.8.8.8", "1.1.1.1", fastLink, mux))

	dnsConfig := netem.NewDNSConfiguration()
	netem.Must0(dnsConfig.AddRecord("dns.google", "", "8.8.8.8"))
	netem.Must0(topology.AddDNSServer("1.1.1.1", "1.1.1.1", fastLink, dnsConfig))

	// create the HTTP transport to use.
	txp := netem.NewHTTPTransport(clientStack)
	defer txp.CloseIdleConnections()

	// send HTTP pings and measure RTT
	ctx := context.Background()
	for idx := 0; idx < 10; idx++ {
		fmt.Printf("> GET http://dns.google/\n")
		req := netem.Must1(http.NewRequestWithContext(ctx, "GET", "http://dns.google/", nil))
		t0 := time.Now()
		resp, err := txp.RoundTrip(req)
		delta := time.Since(t0)
		if err != nil {
			fmt.Printf("< [rtt=%s] %s\n", delta, err.Error())
			time.Sleep(1 * time.Second)
			continue
		}
		fmt.Printf("< [rtt=%s] %d %s\n", delta, resp.StatusCode, http.StatusText(resp.StatusCode))
		time.Sleep(1 * time.Second)
	}
}
