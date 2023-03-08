package netem

//
// HTTP server
//

import (
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/quic-go/quic-go/http3"
)

// HTTPListenAndServe creates a new TCP listener using the stack IP address and starts
// an [http.Server] using such a listener and the given mux.
func HTTPListenAndServe(stack HTTPUnderlyingNetwork, mux http.Handler) error {
	addr := &net.TCPAddr{
		IP:   net.ParseIP(stack.IPAddress()), // already parsed, so we know it's okay
		Port: 80,
		Zone: "",
	}
	listener, err := stack.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}
	stack.Logger().Debugf("netem: http: start %s/tcp", addr.String())
	server := &http.Server{
		Handler:   mux,
		TLSConfig: stack.ServerTLSConfig(),
	}
	err = server.Serve(listener)
	stack.Logger().Debugf("netem: http: stop %s/tcp", addr.String())
	return err
}

// HTTPListenAndServe creates a new TCP listener using the stack IP address and starts
// an [http.Server] using such a listener, TLS, and the given mux.
func HTTPListenAndServeTLS(stack HTTPUnderlyingNetwork, mux http.Handler) error {
	addr := &net.TCPAddr{
		IP:   net.ParseIP(stack.IPAddress()), // already parsed, so we know it's okay
		Port: 443,
		Zone: "",
	}
	listener, err := stack.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}
	stack.Logger().Debugf("netem: http: start %s/tcp", addr.String())
	server := &http.Server{
		Handler:   mux,
		TLSConfig: stack.ServerTLSConfig(),
	}
	err = server.ServeTLS(listener, "", "")
	stack.Logger().Debugf("netem: http: stop %s/tcp", addr.String())
	return err
}

// HTTPListenAndServe creates a new UDP listener using the stack IP address and starts
// an [http.Server] using such a listener, QUIC, and the given mux.
func HTTPListenAndServeQUIC(stack HTTPUnderlyingNetwork, mux http.Handler) error {
	addr := &net.UDPAddr{
		IP:   net.ParseIP(stack.IPAddress()), // already parsed, so we know it's okay
		Port: 443,
		Zone: "",
	}
	pconn, err := stack.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	stack.Logger().Debugf("netem: http: start %s/udp", addr.String())
	server := &http3.Server{
		Handler:   mux,
		TLSConfig: stack.ServerTLSConfig(),
	}
	err = server.Serve(pconn)
	stack.Logger().Debugf("netem: http: stop %s/udp", addr.String())
	return err
}

// HTTPListenAndServeAll combines [HTTPListenAndServer], [HTTPListenAndServeTLS],
// and [HTTPListenAndServeQUIC] into a single function call.
func HTTPListenAndServeAll(stack HTTPUnderlyingNetwork, mux http.Handler) error {
	var (
		wg = &sync.WaitGroup{}
		c  = make(chan error, 1)
		q  = make(chan error, 1)
		s  = make(chan error, 1)
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		c <- HTTPListenAndServe(stack, mux)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		q <- HTTPListenAndServeTLS(stack, mux)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		s <- HTTPListenAndServeQUIC(stack, mux)
	}()

	wg.Wait()

	return NewErrHTTPServeAndListen(<-c, <-q, <-s)
}

// ErrHTTPServeAndListen is the error returned by [HTTPServeAndListenAll].
type ErrHTTPServeAndListen struct {
	TCPError  error
	QUICError error
	TLSError  error
}

var _ error = &ErrHTTPServeAndListen{}

// NewErrHTTPServeAndListen constructs a new [ErrHTTPServeAndListen] instance.
func NewErrHTTPServeAndListen(tcp, quic, tls error) *ErrHTTPServeAndListen {
	return &ErrHTTPServeAndListen{
		TCPError:  tcp,
		QUICError: quic,
		TLSError:  tls,
	}
}

// Error implements error
func (e *ErrHTTPServeAndListen) Error() string {
	return fmt.Sprintf("tcp: %s; -quic: %s; -tls: %s", e.tcp(), e.quic(), e.tls())
}

// tcp returns a string representation of the TCP error.
func (e *ErrHTTPServeAndListen) tcp() string {
	return e.errString(e.TCPError)
}

// quic returns a string representation of the QUIC error.
func (e *ErrHTTPServeAndListen) quic() string {
	return e.errString(e.QUICError)
}

// tls returns a string representation of the TLS error.
func (e *ErrHTTPServeAndListen) tls() string {
	return e.errString(e.TLSError)
}

// errString converts an error to a string dealing gracefully with the nil case.
func (e *ErrHTTPServeAndListen) errString(err error) (out string) {
	switch err {
	case nil:
		return "<nil>"
	default:
		return err.Error()
	}
}
