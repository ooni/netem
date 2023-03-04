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

// HTTPListenAndServe is a replacement for [http.ListenAndServe].
func HTTPListenAndServe(stack HTTPUnderlyingNetwork, server *http.Server) error {
	addr := &net.TCPAddr{
		IP:   net.ParseIP(stack.IPAddress()), // already parsed, so we know it's okay
		Port: 80,
		Zone: "",
	}
	listener, err := stack.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}
	stack.Logger().Infof("netem: http: start %s/tcp", addr.String())
	err = server.Serve(listener)
	stack.Logger().Infof("netem: http: stop %s/tcp", addr.String())
	return err
}

// HTTPListenAndServeTLS is a replacement for [http.ListenAndServeTLS].
//
// Before calling this function you MUST set the server.TLSConfig field to
// be the [TLSMITMConfig] you used when creating the stack.
func HTTPListenAndServeTLS(stack HTTPUnderlyingNetwork, server *http.Server) error {
	addr := &net.TCPAddr{
		IP:   net.ParseIP(stack.IPAddress()), // already parsed, so we know it's okay
		Port: 443,
		Zone: "",
	}
	listener, err := stack.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}
	stack.Logger().Infof("netem: http: start %s/tcp", addr.String())
	err = server.ServeTLS(listener, "", "")
	stack.Logger().Infof("netem: http: stop %s/tcp", addr.String())
	return err
}

// HTTPListenAndServeQUIC is a replacement for [http3.Server.ListenAndServeTLS].
//
// Before calling this function you MUST set the server.TLSConfig field to
// be the [TLSMITMConfig] you used when creating the stack.
func HTTPListenAndServeQUIC(stack HTTPUnderlyingNetwork, server *http3.Server) error {
	addr := &net.UDPAddr{
		IP:   net.ParseIP(stack.IPAddress()), // already parsed, so we know it's okay
		Port: 443,
		Zone: "",
	}
	pconn, err := stack.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	stack.Logger().Infof("netem: http: start %s/udp", addr.String())
	err = server.Serve(pconn)
	stack.Logger().Infof("netem: http: stop %s/udp", addr.String())
	return err
}

// HTTPListenAndServeAll combines [HTTPListenAndServer], [HTTPListenAndServeTLS],
// and [HTTPListenAndServeQUIC] into a single function call.
//
// Before calling this function you MUST set the server's TLSConfig field to
// be the [TLSMITMConfig] you used when creating the stack.
func HTTPListenAndServeAll(
	stack HTTPUnderlyingNetwork,
	tcp *http.Server,
	quic *http3.Server,
) error {
	var (
		wg = &sync.WaitGroup{}
		c  = make(chan error, 1)
		q  = make(chan error, 1)
		s  = make(chan error, 1)
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		c <- HTTPListenAndServe(stack, tcp)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		q <- HTTPListenAndServeTLS(stack, tcp)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		s <- HTTPListenAndServeQUIC(stack, quic)
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

func (e *ErrHTTPServeAndListen) errString(err error) (out string) {
	switch err {
	case nil:
		return "<nil>"
	default:
		return err.Error()
	}
}
