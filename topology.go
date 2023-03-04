package netem

import (
	"net/http"
	"sync"

	"github.com/quic-go/quic-go/http3"
)

// Topology describes a network toplogy. The zero value
// is invalid; please, construct with [NewTopology].
type Topology struct {
	closeOnce sync.Once
	links     []*Link
	logger    Logger
	mitm      *TLSMITMConfig
	mtu       uint32
	router    *Router
}

// NewTopology constructs a new, empty [Topology].
func NewTopology(logger Logger) (*Topology, error) {
	mitmCfg, err := NewTLSMITMConfig()
	if err != nil {
		return nil, err
	}

	top := &Topology{
		closeOnce: sync.Once{},
		links:     []*Link{},
		logger:    logger,
		mitm:      mitmCfg,
		mtu:       1500,
		router:    NewRouter(logger),
	}

	return top, nil
}

// AddHost adds an host to the network topology.
func (t *Topology) AddHost(
	hostAddress string,
	resolverAddress string,
	config *LinkConfig,
) (*UNetStack, error) {
	host, err := NewUNetStack(t.logger, t.mtu, hostAddress, t.mitm, resolverAddress)
	if err != nil {
		return nil, err
	}
	port0 := NewRouterPort(t.router)
	link := NewLink(t.logger, host, port0, config) // TAKES OWNERSHIP of the NICs
	t.links = append(t.links, link)
	t.router.AddRoute(hostAddress, port0)
	return host, nil
}

// AddHTTPServer adds an HTTP server host to the network topology.
func (t *Topology) AddHTTPServer(
	hostAddress string,
	resolverAddress string,
	config *LinkConfig,
	mux http.Handler,
) error {
	host, err := t.AddHost(hostAddress, resolverAddress, config)
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

// AddDNSServer adds a DNS server to the topology.
func (t *Topology) AddDNSServer(
	hostAddress string,
	resolverAddress string,
	config *LinkConfig,
	hostsdb *DNSConfiguration,
) error {
	host, err := t.AddHost(hostAddress, resolverAddress, config)
	if err != nil {
		return err
	}
	_, err = NewDNSServer(t.logger, host, hostAddress, hostsdb)
	return err
}

// Topology closes all the links and routers created by the topology.
func (t *Topology) Close() error {
	t.closeOnce.Do(func() {
		for _, ln := range t.links {
			ln.Close()
		}
		t.router.Close()
	})
	return nil
}
