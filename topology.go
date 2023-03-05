package netem

//
// Network topologies
//

import (
	"net/http"
	"sync"

	"github.com/apex/log"
	"github.com/quic-go/quic-go/http3"
)

// PPPTopology is a point-to-point topology with two network stacks and
// a [Link] in the middle. By convention, the left stack is the client and
// the right one is the server. The zero value of this struct is invalid;
// use [NewPPPTopology] to create a new instance.
type PPPTopology struct {
	// Client is the client network stack in the PPP topology.
	Client *UNetStack

	// Server is the server network stack in the PPP topology.
	Server *UNetStack

	// closeOnce allows to have a "once" semantics for Close
	closeOnce sync.Once

	// link is the link connecting the stacks.
	link *Link
}

// NewPPPTopology creates a [PPPTopology]. Use the Close method to
// shutdown the link created by this topology.
//
// Arguments:
//
// - clientAddress is the client IP address;
//
// - serverAddress is the server IP address;
//
// - logger is the logger to use;
//
// - MTU is the MTU to use (1500 is a good MTU value);
//
// - lc describes the link characteristics;
//
// - dnsConfig contains DNS configuration for the DNS server
// that we will create using the server UNetStack.
func NewPPPTopology(
	clientAddress string,
	serverAddress string,
	logger Logger,
	MTU uint32,
	lc *LinkConfig,
	dnsConfig *DNSConfiguration,
) (*PPPTopology, error) {
	// create configuration for the MITM
	mitmCfg, err := NewTLSMITMConfig()
	if err != nil {
		return nil, err
	}

	// create the client TCP/IP userspace stack
	client, err := NewUNetStack(
		logger,
		MTU,
		clientAddress,
		mitmCfg,
		serverAddress,
	)
	if err != nil {
		return nil, err
	}

	// create the server TCP/IP userspace stack
	server, err := NewUNetStack(
		log.Log,
		MTU,
		serverAddress,
		mitmCfg,
		"0.0.0.0",
	)
	if err != nil {
		client.Close()
		return nil, err
	}

	// create DNS server using the server stack
	_, err = NewDNSServer(
		logger,
		server,
		serverAddress,
		dnsConfig,
	)
	if err != nil {
		client.Close()
		server.Close()
		return nil, err
	}

	// connect the two stacks using a link
	link := NewLink(log.Log, client, server, lc)

	t := &PPPTopology{
		Client:    client,
		Server:    server,
		closeOnce: sync.Once{},
		link:      link,
	}
	return t, nil
}

// Close closes all the hosts and links allocated by the topology
func (t *PPPTopology) Close() error {
	t.closeOnce.Do(func() {
		// note: closing a [Link] also closes the
		// two hosts using the [Link]
		t.link.Close()
	})
	return nil
}

// StarTopology is the star network topology: there is a router in the
// middle and all hosts connect to it. The zero value is invalid; please,
// construct using the [NewStarTopology].
type StarTopology struct {
	// closeOnce allows to have a "once" semantics for Close
	closeOnce sync.Once

	// links contains all the links we have created
	links []*Link

	// logger is the logger to use
	logger Logger

	// mitm is the TLS MITM configuration
	mitm *TLSMITMConfig

	// mtu is the MTU to use
	mtu uint32

	// router is the topology's router
	router *Router
}

// NewStarTopology constructs a new, empty [StarTopology] consisting
// of a [Router] sitting in the middle. Once you have the [StarTopology]
// you can now add hosts using [AddHost], [AddHTTPServer], etc.
func NewStarTopology(logger Logger) (*StarTopology, error) {
	mitmCfg, err := NewTLSMITMConfig()
	if err != nil {
		return nil, err
	}

	t := &StarTopology{
		closeOnce: sync.Once{},
		links:     []*Link{},
		logger:    logger,
		mitm:      mitmCfg,
		mtu:       1500,
		router:    NewRouter(logger),
	}

	return t, nil
}

// AddHost creates a new [UNetStack] and a [RouterPort], creates a
// [Link] to connect them, attaches the port to the topology's [Router],
// and returns the [UNetStack] to the caller. You do not need to call [Close]
// for the returned [UNetStack] because calling the [StartTopology]'s
// Close method will also close the [UNetStack].
//
// Arguments:
//
// - hostAddress is the IPv4 address to assign to the [UNetStack];
//
// - resolverAddress is the IPv4 address of the resolver the [UNetStack]
// should use; use 0.0.0.0 if you don't need DNS resolution;
//
// - lc contains config for the [Link] connecting the [UNetStack]
// to the [Router] of the [StarTopology].
func (t *StarTopology) AddHost(
	hostAddress string,
	resolverAddress string,
	lc *LinkConfig,
) (*UNetStack, error) {
	host, err := NewUNetStack(t.logger, t.mtu, hostAddress, t.mitm, resolverAddress)
	if err != nil {
		return nil, err
	}
	port0 := NewRouterPort(t.router)
	link := NewLink(t.logger, host, port0, lc) // TAKES OWNERSHIP of host and port0
	t.links = append(t.links, link)
	t.router.AddRoute(hostAddress, port0)
	return host, nil
}

// AddHTTPServer calls [StartTopology.AddHost], then creates and HTTP and
// an HTTP3 server, and calls [HTTPListenAndServeAll] to start it.
//
// Arguments are like [StarTopology.AddHost] arguments. The mux is the
// [http.Handler] describing what the created servers should serve.
func (t *StarTopology) AddHTTPServer(
	hostAddress string,
	resolverAddress string,
	lc *LinkConfig,
	mux http.Handler,
) error {
	host, err := t.AddHost(hostAddress, resolverAddress, lc)
	if err != nil {
		return err
	}
	httpServer := &http.Server{
		Handler:   mux,
		TLSConfig: t.mitm.TLSConfig(),
	}
	http3Server := &http3.Server{
		Handler:   mux,
		TLSConfig: t.mitm.TLSConfig(),
	}
	go HTTPListenAndServeAll(host, httpServer, http3Server)
	return nil
}

// AddDNSServer calls [StartTopology.AddHost], then creates and starts a
// DNS server using the [UNetStack] returned by AddHost.
//
// Arguments are like [StarTopology.AddHost] arguments. The hostsdb is the
// [DNSConfiguration] describing what the created server should serve.
func (t *StarTopology) AddDNSServer(
	hostAddress string,
	resolverAddress string,
	lc *LinkConfig,
	hostsdb *DNSConfiguration,
) error {
	host, err := t.AddHost(hostAddress, resolverAddress, lc)
	if err != nil {
		return err
	}
	_, err = NewDNSServer(t.logger, host, hostAddress, hostsdb)
	return err
}

// Close closes (a) the router and (b) all the links and
// the hosts created using this [StarTopology].
func (t *StarTopology) Close() error {
	t.closeOnce.Do(func() {
		for _, ln := range t.links {
			// note: closing a [Link] also closes the
			// two hosts using the [Link]
			ln.Close()
		}
		t.router.Close()
	})
	return nil
}
