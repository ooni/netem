package netem

//
// DNS server
//

import (
	"errors"
	"net"
	"sync"

	"github.com/apex/log"
	"github.com/miekg/dns"
)

// DNSServer is a DNS server. The zero value is invalid,
// please construct using [NewDNSServer].
type DNSServer struct {
	once  sync.Once
	pconn UDPLikeConn
	wg    *sync.WaitGroup
}

// NewDNSServer creates a new [DNSServer] instance. Remember to
// call [DNSServer.Close] when you are done using this server.
//
// The ipAddress argument is the IPv4 DNS server address.
func NewDNSServer(
	logger Logger,
	stack UnderlyingNetwork,
	ipAddress string,
	config *DNSConfiguration,
) (*DNSServer, error) {
	parsedIP := net.ParseIP(ipAddress)
	if parsedIP == nil {
		return nil, ErrNotIPAddress
	}

	// create listening server
	udpAddr := &net.UDPAddr{
		IP:   parsedIP,
		Port: 53,
		Zone: "",
	}
	pconn, err := stack.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	// spawn a single worker
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go dnsServerWorker(logger, ipAddress, config, pconn, wg)

	ds := &DNSServer{
		once:  sync.Once{},
		pconn: pconn,
		wg:    wg,
	}
	return ds, nil
}

// Close shuts down the DNS server
func (ds *DNSServer) Close() error {
	ds.once.Do(func() {
		ds.pconn.Close()
	})
	return nil
}

// dnsRecord is a DNS record in the [dnsConfiguration].
type dnsRecord struct {
	// A is the A resource record.
	A []net.IP

	// CNAME is the CNAME.
	CNAME string
}

// DNSConfiguration is the DNS configuration to use. The zero
// value is invalid; please use [newDNSConfiguration].
type DNSConfiguration struct {
	mu sync.Mutex
	r  map[string]*dnsRecord
}

// NewDNSConfiguration constructs a [dnsConfiguration] instance.
func NewDNSConfiguration() *DNSConfiguration {
	return &DNSConfiguration{
		mu: sync.Mutex{},
		r:  map[string]*dnsRecord{},
	}
}

// ErrNotIPAddress indicates that a string is not a serialized IP address.
var ErrNotIPAddress = errors.New("netem: not a valid IP address")

// AddRecord adds a record to the DNS server's database or returns an error.
func (dc *DNSConfiguration) AddRecord(domain string, cname string, addrs ...string) error {
	var a []net.IP
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			return ErrNotIPAddress
		}
		a = append(a, ip)
	}
	dc.mu.Lock()
	dc.r[dns.CanonicalName(domain)] = &dnsRecord{
		A:     a,
		CNAME: cname,
	}
	dc.mu.Unlock()
	return nil
}

// lookup searches a name inside the [dnsConfiguration].
func (dc *DNSConfiguration) lookup(name string) (*dnsRecord, bool) {
	defer dc.mu.Unlock()
	dc.mu.Lock()
	record, found := dc.r[name]
	return record, found
}

// dnsServerWorker is the [DNSServer] worker.
func dnsServerWorker(
	logger Logger,
	ipAddress string,
	config *DNSConfiguration,
	pconn UDPLikeConn,
	wg *sync.WaitGroup,
) {
	logger.Infof("netem: dns server %s up", ipAddress)
	defer func() {
		logger.Infof("netem: dns server %s down", ipAddress)
		wg.Done()
	}()

	for {
		// read incoming raw query
		buffer := make([]byte, 8000)
		count, addr, err := pconn.ReadFrom(buffer)
		if err != nil {
			log.Warnf("netem: dns: pconn.ReadFrom: %s", err.Error())
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		rawQuery := buffer[:count]

		rawResponse, err := dnsServerRoundTrip(config, rawQuery)
		if err != nil {
			log.Warnf("netem: dnsServerRoundTrip: %s", err.Error())
			continue
		}

		_, _ = pconn.WriteTo(rawResponse, addr)
	}
}

// dnsServerRoundTrip responds to a raw DNS query with a raw DNS response.
func dnsServerRoundTrip(config *DNSConfiguration, rawQuery []byte) ([]byte, error) {
	// parse incoming query
	query := &dns.Msg{}
	if err := query.Unpack(rawQuery); err != nil {
		return nil, err
	}

	// reject blatantly wrong queries
	if query.Response || len(query.Question) != 1 {
		resp := &dns.Msg{}
		resp.SetRcode(query, dns.RcodeRefused)
		return Must1(resp.Pack()), nil
	}

	// find the corresponding record
	q0 := query.Question[0]
	if q0.Qclass != dns.ClassINET {
		resp := &dns.Msg{}
		resp.SetRcode(query, dns.RcodeRefused)
		return Must1(resp.Pack()), nil
	}
	rr, found := config.lookup(q0.Name)

	// handle the NXDOMAIN case
	if !found {
		resp := &dns.Msg{}
		resp.SetRcode(query, dns.RcodeNameError)
		return Must1(resp.Pack()), nil
	}

	return dnsServerNewSuccessfulResponse(query, q0, rr)
}

// dnsServerNewSuccessfulResponse constructs a successful response.
func dnsServerNewSuccessfulResponse(query *dns.Msg, q0 dns.Question, rr *dnsRecord) ([]byte, error) {
	// fill the response
	resp := &dns.Msg{}
	resp.SetReply(query)

	// insert A entries if needed
	if q0.Qtype == dns.TypeA {
		for _, addr := range rr.A {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:     q0.Name,
					Rrtype:   dns.TypeA,
					Class:    dns.ClassINET,
					Ttl:      3600,
					Rdlength: 0,
				},
				A: addr,
			})
		}
	}

	// insert a CNAME entry if needed
	if rr.CNAME != "" {
		resp.Answer = append(resp.Answer, &dns.CNAME{
			Hdr: dns.RR_Header{
				Name:     q0.Name,
				Rrtype:   dns.TypeCNAME,
				Class:    dns.ClassINET,
				Ttl:      3600,
				Rdlength: 0,
			},
			Target: rr.CNAME,
		})
	}

	return Must1(resp.Pack()), nil
}
