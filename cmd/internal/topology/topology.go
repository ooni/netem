// Package topology contains helper code to switch topology in commands.
package topology

import (
	"net/http"
	"time"

	"github.com/apex/log"
	"github.com/bassosimone/netem"
	"github.com/bassosimone/netem/cmd/internal/optional"
	"github.com/quic-go/quic-go/http3"
)

// Closer allows to close an open topology and release all
// the associated hosts and links.
type Closer interface {
	Close() error
}

// New creates a new topology. This function panics on failure.
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
// - dnsConfig contains the DNS config;
//
// - mux is the OPTIONAL http.Handler to use: if this argument is nil,
// we won't construct and start an HTTP server.
func New(
	ppp bool,
	clientAddress string,
	clientLink *netem.LinkConfig,
	serverAddress string,
	dnsConfig *netem.DNSConfiguration,
	mux optional.Value[http.Handler],
) (Closer, *netem.UNetStack) {
	switch ppp {
	case true:
		return NewPPP(clientAddress, clientLink, serverAddress, dnsConfig, mux)
	default:
		return NewStar(clientAddress, clientLink, serverAddress, dnsConfig, mux)
	}
}

// NewStar creates a new star topology. This function panics on failure.
//
// Arguments:
//
// - clientAddress is the client IP address;
//
// - clientLink describes the client's last-mile characteristics;
//
// - serverAddress is the server IP address;
//
// - dnsConfig contains the DNS config;
//
// - mux is the OPTIONAL http.Handler to use: if this argument is nil,
// we won't construct and start an HTTP server.
func NewStar(
	clientAddress string,
	clientLink *netem.LinkConfig,
	serverAddress string,
	dnsConfig *netem.DNSConfiguration,
	mux optional.Value[http.Handler],
) (Closer, *netem.UNetStack) {
	// create an empty topology
	topology := netem.Must1(netem.NewStarTopology(log.Log))

	// add the client to the topology
	clientStack := netem.Must1(topology.AddHost("10.0.0.1", "1.1.1.1", clientLink))

	serverLink := &netem.LinkConfig{
		LeftToRightDelay: 1 * time.Millisecond,
		LeftToRightPLR:   1e-09,
		RightToLeftDelay: 1 * time.Millisecond,
		RightToLeftPLR:   1e-09,
	}

	// maybe add an HTTP server to the topology
	if !mux.Empty() {
		netem.Must0(topology.AddHTTPServer("8.8.8.8", "1.1.1.1", serverLink, mux.Unwrap()))
	}

	// add a DNS server to the topology
	netem.Must0(topology.AddDNSServer("1.1.1.1", "1.1.1.1", serverLink, dnsConfig))
	return topology, clientStack
}

// NewPPP creates a new PPP topology. This function panics on failure.
//
// Arguments:
//
// - clientAddress is the client IP address;
//
// - clientLink describes the client's last-mile characteristics;
//
// - serverAddress is the server IP address;
//
// - dnsConfig contains the DNS config;
//
// - mux is the OPTIONAL http.Handler to use: if this argument is nil,
// we won't construct and start an HTTP server.
func NewPPP(
	clientAddress string,
	clientLink *netem.LinkConfig,
	serverAddress string,
	dnsConfig *netem.DNSConfiguration,
	mux optional.Value[http.Handler],
) (Closer, *netem.UNetStack) {
	topology := netem.Must1(netem.NewPPPTopology(
		clientAddress,
		serverAddress,
		log.Log,
		1500,
		clientLink,
		dnsConfig,
	))
	if !mux.Empty() {
		tcpServer := &http.Server{
			Handler:   mux.Unwrap(),
			TLSConfig: topology.Server.ServerTLSConfig(),
		}
		quicServer := &http3.Server{
			Handler:   mux.Unwrap(),
			TLSConfig: topology.Server.ServerTLSConfig(),
		}
		go netem.HTTPListenAndServeAll(topology.Server, tcpServer, quicServer)
	}
	return topology, topology.Client
}
