package netem

//
// Network topologies
//

import (
	"errors"
	"fmt"
	"sync"
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
// - lc describes the link characteristics.
func NewPPPTopology(
	clientAddress string,
	serverAddress string,
	logger Logger,
	lc *LinkConfig,
) (*PPPTopology, error) {
	// create configuration for the MITM
	mitmCfg, err := NewTLSMITMConfig()
	if err != nil {
		return nil, err
	}

	// create the client TCP/IP userspace stack
	const MTU = 1500
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
		logger,
		MTU,
		serverAddress,
		mitmCfg,
		"0.0.0.0",
	)
	if err != nil {
		client.Close()
		return nil, err
	}

	// connect the two stacks using a link
	link := NewLink(logger, client, server, lc)

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
	// addresses tracks the already-added addresses
	addresses map[string]int

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
		addresses: map[string]int{},
		closeOnce: sync.Once{},
		links:     []*Link{},
		logger:    logger,
		mitm:      mitmCfg,
		mtu:       1500,
		router:    NewRouter(logger),
	}

	return t, nil
}

// ErrDuplicateAddr indicates that an address has already been added to a topology.
var ErrDuplicateAddr = errors.New("netem: address has already been added")

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
	if t.addresses[hostAddress] > 0 {
		return nil, fmt.Errorf("%w: %s", ErrDuplicateAddr, hostAddress)
	}
	host, err := NewUNetStack(t.logger, t.mtu, hostAddress, t.mitm, resolverAddress)
	if err != nil {
		return nil, err
	}
	port0 := NewRouterPort(t.router)
	link := NewLink(t.logger, host, port0, lc) // TAKES OWNERSHIP of host and port0
	t.links = append(t.links, link)
	t.router.AddRoute(hostAddress, port0)
	t.addresses[hostAddress]++
	return host, nil
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
	})
	return nil
}

// TLSMITMConfig exposes the [TLSMITMConfig].
func (t *StarTopology) TLSMITMConfig() *TLSMITMConfig {
	return t.mitm
}
