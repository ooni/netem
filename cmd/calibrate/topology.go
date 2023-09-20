package main

//
// Helpers to create PPP or Star topology
//

import (
	"time"

	"github.com/apex/log"
	"github.com/ooni/netem"
)

// topologyCloser allows to close an open topology and release all
// the associated hosts and links.
type topologyCloser interface {
	Close() error
}

// newTopology creates a new topology. This function panics on failure.
//
// Arguments:
//
// - ppp is true when you want a PPP topology and false when
// instead you want a start topology using a router;
//
// - clientAddress is the client IP address;
//
// - clientLink describes the client's last-mile characteristics;
//
// - serverAddress is the server IP address;
//
// - dnsConfig contains the DNS config.
func newTopology(
	ppp bool,
	clientAddress string,
	clientLink *netem.LinkConfig,
	serverAddress string,
	dnsConfig *netem.DNSConfig,
) (topologyCloser, *netem.UNetStack, *netem.UNetStack) {
	switch ppp {
	case true:
		return newTopologyPPP(clientAddress, clientLink, serverAddress, dnsConfig)
	default:
		return newTopologyStar(clientAddress, clientLink, serverAddress, dnsConfig)
	}
}

// newTopologyStar creates a new star topology. This function panics on failure.
//
// Arguments:
//
// - clientAddress is the client IP address;
//
// - clientLink describes the client's last-mile characteristics;
//
// - serverAddress is the server IP address;
//
// - dnsConfig contains the DNS config.
func newTopologyStar(
	clientAddress string,
	clientLink *netem.LinkConfig,
	serverAddress string,
	dnsConfig *netem.DNSConfig,
) (topologyCloser, *netem.UNetStack, *netem.UNetStack) {
	// create an empty topology
	topology := netem.MustNewStarTopology(log.Log)

	// add the client to the topology
	clientStack := netem.Must1(topology.AddHost(clientAddress, serverAddress, clientLink))

	// add the server to the topology
	serverLink := &netem.LinkConfig{
		LeftToRightDelay: 1 * time.Millisecond,
		LeftToRightPLR:   1e-09,
		RightToLeftDelay: 1 * time.Millisecond,
		RightToLeftPLR:   1e-09,
	}
	serverStack := netem.Must1(topology.AddHost(serverAddress, serverAddress, serverLink))

	// create DNS server using the server stack
	_ = netem.Must1(netem.NewDNSServer(log.Log, serverStack, serverAddress, dnsConfig))

	return topology, clientStack, serverStack
}

// newTopologyPPP creates a new PPP topology. This function panics on failure.
//
// Arguments:
//
// - clientAddress is the client IP address;
//
// - clientLink describes the client's last-mile characteristics;
//
// - serverAddress is the server IP address;
//
// - dnsConfig contains the DNS config.
func newTopologyPPP(
	clientAddress string,
	clientLink *netem.LinkConfig,
	serverAddress string,
	dnsConfig *netem.DNSConfig,
) (topologyCloser, *netem.UNetStack, *netem.UNetStack) {
	// create a PPP topology
	topology := netem.MustNewPPPTopology(
		clientAddress,
		serverAddress,
		log.Log,
		clientLink,
	)

	// create DNS server using the server stack
	_ = netem.Must1(netem.NewDNSServer(log.Log, topology.Server, serverAddress, dnsConfig))

	return topology, topology.Client, topology.Server
}
