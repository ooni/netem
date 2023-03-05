// Command dnsping measures the RTT using DNS round trips.
package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/apex/log"
	"github.com/bassosimone/netem"
)

func main() {
	maxPings := flag.Int("count", 10, "number of DNS pings to send")
	flag.Parse()

	// create an empty star topology
	topology := netem.Must1(netem.NewStarTopology(log.Log))
	defer topology.Close()

	// add the client to the empty topology
	slowLink := &netem.LinkConfig{
		LeftToRightDelay: 30 * time.Millisecond,
		LeftToRightPLR:   1e-06,
		RightToLeftDelay: 30 * time.Millisecond,
		RightToLeftPLR:   1e-06,
	}
	clientStack := netem.Must1(topology.AddHost("10.0.0.1", "1.1.1.1", slowLink))

	// add a DNS server to the topology
	fastLink := &netem.LinkConfig{
		LeftToRightDelay: 1 * time.Millisecond,
		LeftToRightPLR:   1e-09,
		RightToLeftDelay: 1 * time.Millisecond,
		RightToLeftPLR:   1e-09,
	}
	dnsConfig := netem.NewDNSConfiguration()
	netem.Must0(dnsConfig.AddRecord("dns.google", "dns.google.com.", "8.8.8.8"))
	netem.Must0(topology.AddDNSServer("1.1.1.1", "1.1.1.1", fastLink, dnsConfig))

	// send DNS pings and measure RTT
	ctx := context.Background()
	for idx := 0; idx < *maxPings; idx++ {
		fmt.Printf("> A? dns.google @8.8.8.8\n")
		query := netem.DNSNewRequestA("dns.google")
		t0 := time.Now()
		response, err := netem.DNSRoundTrip(ctx, clientStack, "1.1.1.1", query)
		delta := time.Since(t0)

		if err != nil {
			fmt.Printf("< [rtt=%s] %s\n", delta, err.Error())
			time.Sleep(1 * time.Second)
			continue
		}

		addrs, cname := netem.Must2(netem.DNSParseResponse(query, response))
		fmt.Printf(
			"< [rtt=%s] Rcode=%d Addrs=%v CNAME=%s\n",
			delta,
			response.Rcode,
			addrs,
			cname,
		)
		time.Sleep(1 * time.Second)
	}
}
