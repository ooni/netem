package netem

//
// DPI: rules to block flows
//

import (
	"bytes"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
)

// DPIResetTrafficForTLSSNI is a [DPIRule] that spoofs a RST TCP segment
// after it sees a given TLS SNI. The zero value is invalid; please, fill
// all the fields marked as MANDATORY.
//
// Note: this rule assumes that there is a router in the path that
// can generate a spoofed RST segment. If there is no router in the
// path, no RST segment will ever be generated.
//
// Note: this rule relies on a race condition. For consistent results
// you MUST set some delay in the router<->server link.
type DPIResetTrafficForTLSSNI struct {
	// Logger is the MANDATORY logger.
	Logger Logger

	// SNI is the MANDATORY offending SNI.
	SNI string

	// TLSHandshake
	TLSHandshake []byte

	// TLSHandshakeSize
	TlSHandshakeSize uint16

	done bool
}

var _ DPIRule = &DPIResetTrafficForTLSSNI{}

// Filter implements DPIRule
func (r *DPIResetTrafficForTLSSNI) Filter(
	direction DPIDirection, packet *DissectedPacket) (*DPIPolicy, bool) {
	// short circuit for the return path
	if direction != DPIDirectionClientToServer {
		return nil, false
	}

	// short circuit for UDP packets
	if packet.TransportProtocol() != layers.IPProtocolTCP {
		return nil, false
	}

	// short circuit in case of misconfiguration
	if r.SNI == "" {
		return nil, false
	}

	// try to obtain the SNI
	tlsHandshakeBytes, length, err := packet.extractTLSHandshake(r.TLSHandshake, r.TlSHandshakeSize)
	if err != nil {
		return nil, false
	}
	if r.TlSHandshakeSize == 0 {
		r.TlSHandshakeSize = length
	}
	r.TLSHandshake = tlsHandshakeBytes
	if r.done {
		return nil, false
	}

	if len(r.TLSHandshake) >= int(r.TlSHandshakeSize) {
		sni, err := packet.parseTLSServerName(r.TLSHandshake[:int(r.TlSHandshakeSize)])
		if err != nil {
			r.Logger.Warnf(
				"netem: dpi: failed to parse TLS server name for %s:%d %s:%d/%s because SNI==%s",
				packet.SourceIPAddress(),
				packet.SourcePort(),
				packet.DestinationIPAddress(),
				packet.DestinationPort(),
				packet.TransportProtocol(),
				sni,
			)
			r.TLSHandshake = []byte{}
			r.TlSHandshakeSize = 0
			return nil, false
		}

		r.TLSHandshake = []byte{}
		r.TlSHandshakeSize = 0
		r.done = true

		// if the packet is not offending, accept it
		if sni != r.SNI {
			return nil, false
		}

		// generate the frame to spoof
		spoofed, err := reflectDissectedTCPSegmentWithRSTFlag(packet)
		if err != nil {
			return nil, false
		}

		// tell the user we're asking the router to RST the flow.
		r.Logger.Infof(
			"netem: dpi: asking to send RST to flow %s:%d %s:%d/%s because SNI==%s",
			packet.SourceIPAddress(),
			packet.SourcePort(),
			packet.DestinationIPAddress(),
			packet.DestinationPort(),
			packet.TransportProtocol(),
			sni,
		)

		// make sure the router knows it should spoof
		policy := &DPIPolicy{
			Delay:   0,
			Flags:   FrameFlagSpoof,
			PLR:     0,
			Spoofed: [][]byte{spoofed},
		}

		return policy, true
	}

	return nil, false
}

// DPIResetTrafficForString is a [DPIRule] that spoofs a RST TCP segment
// after it sees a given string in the payload for a given offending server
// endpoint. The zero value is invalid; please, fill all the fields
// marked as MANDATORY.
//
// Note: this rule assumes that there is a router in the path that
// can generate a spoofed RST segment. If there is no router in the
// path, no RST segment will ever be generated.
//
// Note: this rule relies on a race condition. For consistent results
// you MUST set some delay in the router<->server link.
type DPIResetTrafficForString struct {
	// Logger is the MANDATORY logger.
	Logger Logger

	// ServerIPAddress is the MANDATORY server endpoint IP address.
	ServerIPAddress string

	// ServerPort is the MANDATORY server endpoint port.
	ServerPort uint16

	// String is the MANDATORY offending string.
	String string
}

var _ DPIRule = &DPIResetTrafficForString{}

// Filter implements DPIRule
func (r *DPIResetTrafficForString) Filter(
	direction DPIDirection, packet *DissectedPacket) (*DPIPolicy, bool) {
	// short circuit for the return path
	if direction != DPIDirectionClientToServer {
		return nil, false
	}

	// short circuit for UDP packets
	if packet.TransportProtocol() != layers.IPProtocolTCP {
		return nil, false
	}

	// make sure the remote server is filtered
	if !packet.MatchesDestination(layers.IPProtocolTCP, r.ServerIPAddress, r.ServerPort) {
		return nil, false
	}

	// short circuit in case of misconfiguration
	if r.String == "" {
		return nil, false
	}

	// if the packet is not offending, accept it
	if !bytes.Contains(packet.TCP.Payload, []byte(r.String)) {
		return nil, false
	}

	// generate the frame to spoof
	spoofed, err := reflectDissectedTCPSegmentWithRSTFlag(packet)
	if err != nil {
		return nil, false
	}

	// tell the user we're asking the router to RST the flow.
	r.Logger.Infof(
		"netem: dpi: asking to send RST to flow %s:%d %s:%d/%s because it contains %s",
		packet.SourceIPAddress(),
		packet.SourcePort(),
		packet.DestinationIPAddress(),
		packet.DestinationPort(),
		packet.TransportProtocol(),
		r.String,
	)

	// make sure the router knows it should spoof
	policy := &DPIPolicy{
		Delay:   0,
		Flags:   FrameFlagSpoof,
		PLR:     0,
		Spoofed: [][]byte{spoofed},
	}

	return policy, true
}

// DPISpoofDNSResponse is a [DPIRule] that spoofs a DNS response after it
// sees a given DNS request. The zero value is invalid; please, fill all
// the fields marked as MANDATORY.
//
// Note: this rule assumes that there is a router in the path that
// can generate a spoofed RST segment. If there is no router in the
// path, no RST segment will ever be generated.
//
// Note: this rule relies on a race condition. For consistent results
// you MUST set some delay in the router<->server link.
type DPISpoofDNSResponse struct {
	// Addresses contains the OPTIONAL addresses to include
	// in the spoofed response. If this field is empty, we
	// will return a NXDOMAIN response to the user.
	Addresses []string

	// Logger is the MANDATORY logger.
	Logger Logger

	// Domain is the MANDATORY offending SNI.
	Domain string
}

var _ DPIRule = &DPISpoofDNSResponse{}

// Filter implements DPIRule
func (r *DPISpoofDNSResponse) Filter(
	direction DPIDirection, packet *DissectedPacket) (*DPIPolicy, bool) {
	// short circuit for the return path
	if direction != DPIDirectionClientToServer {
		return nil, false
	}

	// short circuit for TCP packets
	if packet.TransportProtocol() != layers.IPProtocolUDP {
		return nil, false
	}

	// short circuit for non-DNS traffic
	if packet.DestinationPort() != 53 {
		return nil, false
	}

	// short circuit in case of misconfiguration
	if r.Domain == "" {
		return nil, false
	}

	// try to parse the DNS request
	request := &dns.Msg{}
	if err := request.Unpack(packet.UDP.Payload); err != nil {
		return nil, false
	}

	// if the packet is not offending, accept it
	if len(request.Question) != 1 {
		return nil, false
	}
	question := request.Question[0]
	if question.Name != dns.CanonicalName(r.Domain) {
		return nil, false
	}

	// create a DNS record for preparing a response
	dnsRecord := &DNSRecord{
		A:     []net.IP{},
		CNAME: "",
	}
	for _, addr := range r.Addresses {
		if ip := net.ParseIP(addr); ip != nil {
			dnsRecord.A = append(dnsRecord.A, ip)
		}
	}

	// generate raw DNS response
	rawResponse, err := dnsServerNewResponse(request, question, len(dnsRecord.A) > 0, dnsRecord)
	if err != nil {
		return nil, false
	}

	// generate the frame to spoof
	spoofed, err := reflectDissectedUDPDatagramWithPayload(packet, rawResponse)
	if err != nil {
		return nil, false
	}

	// make sure the router knows it should spoof
	policy := &DPIPolicy{
		Delay:   0,
		Flags:   FrameFlagSpoof,
		PLR:     0,
		Spoofed: [][]byte{spoofed},
	}

	// tell the user we're asking the router to spoof a response
	r.Logger.Infof(
		"netem: dpi: asking to spoof DNS reply for flow %s:%d %s:%d/%s because domain==%s",
		packet.SourceIPAddress(),
		packet.SourcePort(),
		packet.DestinationIPAddress(),
		packet.DestinationPort(),
		packet.TransportProtocol(),
		question.Name,
	)

	return policy, true
}

// DPICloseConnectionForTLSSNI is a [DPIRule] that spoofs a FIN|ACK TCP segment
// after it sees a given TLS SNI. The zero value is invalid; please, fill
// all the fields marked as MANDATORY.
//
// Note: this rule assumes that there is a router in the path that
// can generate a spoofed RST segment. If there is no router in the
// path, no RST segment will ever be generated.
//
// Note: this rule relies on a race condition. For consistent results
// you MUST set some delay in the router<->server link.
type DPICloseConnectionForTLSSNI struct {
	// Logger is the MANDATORY logger.
	Logger Logger

	// SNI is the MANDATORY offending SNI.
	SNI string

	// TLSHandshake
	TLSHandshake []byte

	// TLSHandshakeSize
	TlSHandshakeSize uint16
}

var _ DPIRule = &DPICloseConnectionForTLSSNI{}

// Filter implements DPIRule
func (r *DPICloseConnectionForTLSSNI) Filter(
	direction DPIDirection, packet *DissectedPacket) (*DPIPolicy, bool) {
	// short circuit for the return path
	if direction != DPIDirectionClientToServer {
		return nil, false
	}

	// short circuit for UDP packets
	if packet.TransportProtocol() != layers.IPProtocolTCP {
		return nil, false
	}

	// short circuit in case of misconfiguration
	if r.SNI == "" {
		return nil, false
	}

	// try to obtain the SNI
	tlsHandshakeBytes, length, err := packet.extractTLSHandshake(r.TLSHandshake, r.TlSHandshakeSize)
	if err != nil {
		return nil, false
	}
	if r.TlSHandshakeSize == 0 {
		r.TlSHandshakeSize = length
	}
	r.TLSHandshake = tlsHandshakeBytes

	if len(r.TLSHandshake) == int(r.TlSHandshakeSize) {
		sni, err := packet.parseTLSServerName(r.TLSHandshake)
		if err != nil {
			return nil, false
		}
		// if the packet is not offending, accept it
		if sni != r.SNI {
			return nil, false
		}

		// generate the frame to spoof
		spoofed, err := reflectDissectedTCPSegmentWithFINACKFlag(packet)
		if err != nil {
			return nil, false
		}

		// tell the user we're asking the router to FIN|ACK the flow.
		r.Logger.Infof(
			"netem: dpi: asking to send FIN|ACK to flow %s:%d %s:%d/%s because SNI==%s",
			packet.SourceIPAddress(),
			packet.SourcePort(),
			packet.DestinationIPAddress(),
			packet.DestinationPort(),
			packet.TransportProtocol(),
			sni,
		)

		// make sure the router knows it should spoof
		policy := &DPIPolicy{
			Delay:   0,
			Flags:   FrameFlagSpoof,
			PLR:     0,
			Spoofed: [][]byte{spoofed},
		}

		return policy, true
	}

	return nil, false

}

// DPICloseConnectionForServerEndpoint is a [DPIRule] that spoofs a FIN|ACK TCP segment
// after it sees a given TCP connect attempt. The zero value is invalid; please, fill
// all the fields marked as MANDATORY.
//
// Note: this rule assumes that there is a router in the path that
// can generate a spoofed RST segment. If there is no router in the
// path, no RST segment will ever be generated.
//
// Note: this rule relies on a race condition. For consistent results
// you MUST set some delay in the router<->server link.
type DPICloseConnectionForServerEndpoint struct {
	// Logger is the MANDATORY logger.
	Logger Logger

	// ServerIPAddress is the MANDATORY server endpoint IP address.
	ServerIPAddress string

	// ServerPort is the MANDATORY server endpoint port.
	ServerPort uint16
}

var _ DPIRule = &DPICloseConnectionForServerEndpoint{}

// Filter implements DPIRule
func (r *DPICloseConnectionForServerEndpoint) Filter(
	direction DPIDirection, packet *DissectedPacket) (*DPIPolicy, bool) {
	// make sure the packet is TCP and for the proper endpoint
	if !packet.MatchesDestination(layers.IPProtocolTCP, r.ServerIPAddress, r.ServerPort) {
		return nil, false
	}

	// generate the frame to spoof
	spoofed, err := reflectDissectedTCPSegmentWithSetter(packet, func(tcp *layers.TCP) {
		tcp.RST = true
		tcp.ACK = true
	})

	// make sure we could spoof the packet
	if err != nil {
		return nil, false
	}

	// tell the user we're asking the router to RST|ACK the flow.
	r.Logger.Infof(
		"netem: dpi: asking to send RST|ACK to flow %s:%d %s:%d/%s because it is filtered",
		packet.SourceIPAddress(),
		packet.SourcePort(),
		packet.DestinationIPAddress(),
		packet.DestinationPort(),
		packet.TransportProtocol(),
	)

	// make sure the router knows it should spoof
	policy := &DPIPolicy{
		Delay:   0,
		Flags:   FrameFlagSpoof,
		PLR:     0,
		Spoofed: [][]byte{spoofed},
	}

	return policy, true
}

// DPICloseConnectionForString is a [DPIRule] that spoofs a FIN|ACK TCP segment
// after it sees a given string in the payload. The zero value is invalid; please, fill
// all the fields marked as MANDATORY.
//
// Note: this rule assumes that there is a router in the path that
// can generate a spoofed RST segment. If there is no router in the
// path, no RST segment will ever be generated.
//
// Note: this rule relies on a race condition. For consistent results
// you MUST set some delay in the router<->server link.
type DPICloseConnectionForString struct {
	// Logger is the MANDATORY logger.
	Logger Logger

	// ServerIPAddress is the MANDATORY server endpoint IP address.
	ServerIPAddress string

	// ServerPort is the MANDATORY server endpoint port.
	ServerPort uint16

	// SNI is the MANDATORY offending string.
	String string
}

var _ DPIRule = &DPICloseConnectionForString{}

// Filter implements DPIRule
func (r *DPICloseConnectionForString) Filter(
	direction DPIDirection, packet *DissectedPacket) (*DPIPolicy, bool) {
	// short circuit for the return path
	if direction != DPIDirectionClientToServer {
		return nil, false
	}

	// short circuit for UDP packets
	if packet.TransportProtocol() != layers.IPProtocolTCP {
		return nil, false
	}

	// make sure the remote server is filtered
	if !packet.MatchesDestination(layers.IPProtocolTCP, r.ServerIPAddress, r.ServerPort) {
		return nil, false
	}

	// short circuit in case of misconfiguration
	if r.String == "" {
		return nil, false
	}

	// if the packet is not offending, accept it
	if !bytes.Contains(packet.TCP.Payload, []byte(r.String)) {
		return nil, false
	}

	// generate the frame to spoof
	spoofed, err := reflectDissectedTCPSegmentWithFINACKFlag(packet)
	if err != nil {
		return nil, false
	}

	// tell the user we're asking the router to FIN|ACK the flow.
	r.Logger.Infof(
		"netem: dpi: asking to send FIN|ACK to flow %s:%d %s:%d/%s because it contains %s",
		packet.SourceIPAddress(),
		packet.SourcePort(),
		packet.DestinationIPAddress(),
		packet.DestinationPort(),
		packet.TransportProtocol(),
		r.String,
	)

	// make sure the router knows it should spoof
	policy := &DPIPolicy{
		Delay:   0,
		Flags:   FrameFlagSpoof,
		PLR:     0,
		Spoofed: [][]byte{spoofed},
	}

	return policy, true
}

// DPISpoofBlockpageForString is a [DPIRule] that spoofs a blockpage
// after it sees a given string in the payload. The zero value is invalid; please, fill
// all the fields marked as MANDATORY.
//
// Note: this rule assumes that there is a router in the path that
// can generate a spoofed RST segment. If there is no router in the
// path, no RST segment will ever be generated.
//
// Note: this rule relies on a race condition. For consistent results
// you MUST set some delay in the router<->server link.
//
// Note: this rule requires the blockpage to be very small.
type DPISpoofBlockpageForString struct {
	// HTTPResponse is the MANDATORY blockpage content prefix with HTTP
	// headers (use DPIFormatHTTPResponse to produce this field).
	HTTPResponse []byte

	// Logger is the MANDATORY logger.
	Logger Logger

	// ServerIPAddress is the MANDATORY server endpoint IP address.
	ServerIPAddress string

	// ServerPort is the MANDATORY server endpoint port.
	ServerPort uint16

	// SNI is the MANDATORY offending string.
	String string
}

var _ DPIRule = &DPISpoofBlockpageForString{}

// Filter implements DPIRule
func (r *DPISpoofBlockpageForString) Filter(
	direction DPIDirection, packet *DissectedPacket) (*DPIPolicy, bool) {
	// short circuit for the return path
	if direction != DPIDirectionClientToServer {
		return nil, false
	}

	// short circuit for UDP packets
	if packet.TransportProtocol() != layers.IPProtocolTCP {
		return nil, false
	}

	// make sure the remote server is filtered
	if !packet.MatchesDestination(layers.IPProtocolTCP, r.ServerIPAddress, r.ServerPort) {
		return nil, false
	}

	// short circuit in case of misconfiguration
	if r.String == "" {
		return nil, false
	}

	// if the packet is not offending, accept it
	if !bytes.Contains(packet.TCP.Payload, []byte(r.String)) {
		return nil, false
	}

	// generate the frame to spoof
	reflected, err := packet.reflectSegment()
	if err != nil {
		return nil, false
	}
	reflected.tcp.ACK = true
	reflected.tcp.FIN = true
	spoofed, err := reflected.serialize(gopacket.Payload(r.HTTPResponse))
	if err != nil {
		return nil, false
	}

	// tell the user we're asking the router to spoof a blockpage.
	r.Logger.Infof(
		"netem: dpi: spoofing blockpage to flow %s:%d %s:%d/%s because it contains %s",
		packet.SourceIPAddress(),
		packet.SourcePort(),
		packet.DestinationIPAddress(),
		packet.DestinationPort(),
		packet.TransportProtocol(),
		r.String,
	)

	// make sure the router knows it should spoof
	policy := &DPIPolicy{
		Delay:   0,
		Flags:   FrameFlagSpoof,
		PLR:     0,
		Spoofed: [][]byte{spoofed},
	}

	return policy, true
}

// DPIFormatHTTPResponse formats an HTTP response for a blockpage.
func DPIFormatHTTPResponse(blockpage []byte) (output []byte) {
	output = append(output, []byte("HTTP/1.0 200 OK\r\n\r\n")...)
	output = append(output, blockpage...)
	return
}
