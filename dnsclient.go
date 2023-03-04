package netem

//
// DNS client code
//

import (
	"context"
	"errors"
	"net"

	"github.com/miekg/dns"
)

// DNSRoundTrip performs a DNS round trip using a given [UnderlyingNetwork].
func DNSRoundTrip(
	ctx context.Context,
	stack UnderlyingNetwork,
	ipAddress string,
	query *dns.Msg,
) (*dns.Msg, error) {
	responsech := make(chan *dns.Msg, 1)
	errch := make(chan error, 1)
	go dnsRoundTripAsync(ctx, stack, ipAddress, query, responsech, errch)
	select {
	case resp := <-responsech:
		return resp, nil
	case err := <-errch:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// dnsRoundTripAsync is an async DNS round trip.
func dnsRoundTripAsync(
	ctx context.Context,
	stack UnderlyingNetwork,
	ipAddress string,
	query *dns.Msg,
	responsech chan<- *dns.Msg,
	errch chan<- error,
) {
	response, err := dnsRoundTrip(ctx, stack, ipAddress, query)
	if err != nil {
		errch <- err
		return
	}
	responsech <- response
}

// dnsRoundTrip performs a DNS round trip using a given [UnderlyingNetwork].
func dnsRoundTrip(
	ctx context.Context,
	stack UnderlyingNetwork,
	ipAddress string,
	query *dns.Msg,
) (*dns.Msg, error) {
	// create an UDP network connection
	addrport := net.JoinHostPort(ipAddress, "53")
	conn, err := stack.DialContext(ctx, "udp", addrport)
	if err != nil {
		return nil, err
	}
	if deadline, good := ctx.Deadline(); good {
		_ = conn.SetDeadline(deadline)
	}
	defer conn.Close()

	// serialize the DNS query
	rawQuery, err := query.Pack()
	if err != nil {
		return nil, err
	}

	// send the query
	if _, err := conn.Write(rawQuery); err != nil {
		return nil, err
	}

	// receive the response from the DNS server
	buffer := make([]byte, 8000)
	count, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}
	rawResponse := buffer[:count]

	// unmarshal the response
	response := &dns.Msg{}
	if err := response.Unpack(rawResponse); err != nil {
		return nil, err
	}
	return response, nil
}

// ErrDNSNoAnswer is returned when the server response does not contain any
// answer for the original query (i.e., no IPv4 addresses).
var ErrDNSNoAnswer = errors.New("netem: dns: no answer from DNS server")

// ErrDNSNoSuchHost is returned in case of NXDOMAIN.
var ErrDNSNoSuchHost = errors.New("netem: dns: no such host")

// ErrDNSServerMisbehaving is the error we return for cases different from NXDOMAIN.
var ErrDNSServerMisbehaving = errors.New("netem: dns: server misbehaving")

// DNSParseResponse parses a [dns.Msg] into a getaddrinfo response
func DNSParseResponse(query, resp *dns.Msg) ([]string, string, error) {
	// make sure resp is a response and relates to the original query ID
	if !resp.Response {
		return nil, "", ErrDNSServerMisbehaving
	}
	if resp.Id != query.Id {
		return nil, "", ErrDNSServerMisbehaving
	}

	// attempt to map errors like the Go standard library would do
	switch resp.Rcode {
	case dns.RcodeSuccess:
		// continue processing the response
	case dns.RcodeNameError:
		return nil, "", ErrDNSNoSuchHost
	default:
		return nil, "", ErrDNSServerMisbehaving
	}

	// search for A answers and CNAME
	var (
		A     []string
		CNAME string
	)
	for _, answer := range resp.Answer {
		switch v := answer.(type) {
		case *dns.A:
			A = append(A, v.A.String())
		case *dns.CNAME:
			CNAME = v.Target
		}
	}

	// make sure we emit the same error the Go stdlib emits
	if len(A) <= 0 {
		return nil, "", ErrDNSNoAnswer
	}

	return A, CNAME, nil
}

// DNSNewRequestA creates a new A request.
func DNSNewRequestA(domain string) *dns.Msg {
	query := &dns.Msg{}
	query.RecursionDesired = true
	query.Id = dns.Id()
	query.Question = []dns.Question{{
		Name:   dns.CanonicalName(domain),
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}}
	return query
}
