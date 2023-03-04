package netem

//
// HTTP client
//

import (
	"crypto/tls"
	"net/http"
)

// HTTPUnderlyingNetwork is the [UnderlyingNetwork] used by HTTP code.
type HTTPUnderlyingNetwork interface {
	UnderlyingNetwork
	IPAddress() string
	Logger() Logger
	TLSConfig() *tls.Config
}

// NewHTTPTransport creates a new [http.Transport] using an [UnderlyingNetwork].
//
// We fill the following fields of the transport:
//
// - DialContext to call a dialing function that will eventually use [stack.DialContext];
//
// - TLSClientConfig to use the stack's [MITMConfig];
//
// - ForceAttemptHTTP2 to force enabling the HTTP/2 protocol.
func NewHTTPTransport(stack HTTPUnderlyingNetwork) *http.Transport {
	net := &Net{stack}
	return &http.Transport{
		DialContext:       net.DialContext,
		TLSClientConfig:   stack.TLSConfig(),
		ForceAttemptHTTP2: true,
	}
}
