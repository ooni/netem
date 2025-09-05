package netem

//
// DPI: rules to throttle flows
//

import (
	"time"

	"github.com/google/gopacket/layers"
)

// DPIThrottleTrafficForTLSSNI is a [DPIRule] that throttles traffic
// after it sees a given TLS SNI. The zero value is not valid. Make sure
// you initialize all fields marked as MANDATORY.
type DPIThrottleTrafficForTLSSNI struct {
	// Delay is the OPTIONAL extra delay to add to the flow.
	Delay time.Duration

	// Logger is the MANDATORY logger to use.
	Logger Logger

	// PLR is the OPTIONAL extra packet loss rate to apply to the packet.
	PLR float64

	// SNI is the OPTIONAL offending SNI
	SNI string

	// TLSHandshake
	TLSHandshake []byte

	// TLSHandshakeSize
	TlSHandshakeSize uint16

	// done
	done bool
}

var _ DPIRule = &DPIThrottleTrafficForTLSSNI{}

// Filter implements DPIRule
func (r *DPIThrottleTrafficForTLSSNI) Filter(
	direction DPIDirection, packet *DissectedPacket) (*DPIPolicy, bool) {
	// short circuit for the return path
	if direction != DPIDirectionClientToServer {
		return nil, false
	}

	// short circuit for UDP packets
	if packet.TransportProtocol() != layers.IPProtocolTCP {
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

	if len(r.TLSHandshake) == int(r.TlSHandshakeSize) {
		sni, err := packet.parseTLSServerName(r.TLSHandshake)
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

		r.Logger.Infof(
			"netem: dpi: throttling flow %s:%d %s:%d/%s because SNI==%s",
			packet.SourceIPAddress(),
			packet.SourcePort(),
			packet.DestinationIPAddress(),
			packet.DestinationPort(),
			packet.TransportProtocol(),
			sni,
		)

		policy := &DPIPolicy{
			Delay:   r.Delay,
			Flags:   0,
			PLR:     r.PLR,
			Spoofed: nil,
		}

		return policy, true
	}

	return nil, false
}

// DPIThrottleTrafficForTCPEndpoint is a [DPIRule] that throttles traffic
// for a given TCP endpoint. The zero value is not valid. Make sure
// you initialize all fields marked as MANDATORY.
type DPIThrottleTrafficForTCPEndpoint struct {
	// Delay is the OPTIONAL extra delay to add to the flow.
	Delay time.Duration

	// Logger is the MANDATORY logger to use.
	Logger Logger

	// PLR is the OPTIONAL extra packet loss rate to apply to the packet.
	PLR float64

	// ServerIPAddress is the MANDATORY server endpoint IP address.
	ServerIPAddress string

	// ServerPort is the MANDATORY server endpoint port.
	ServerPort uint16
}

var _ DPIRule = &DPIThrottleTrafficForTCPEndpoint{}

// Filter implements DPIRule
func (r *DPIThrottleTrafficForTCPEndpoint) Filter(
	direction DPIDirection, packet *DissectedPacket) (*DPIPolicy, bool) {
	// short circuit for the return path
	if direction != DPIDirectionClientToServer {
		return nil, false
	}

	// make sure the packet is TCP and for the proper endpoint
	if !packet.MatchesDestination(layers.IPProtocolTCP, r.ServerIPAddress, r.ServerPort) {
		return nil, false
	}

	r.Logger.Infof(
		"netem: dpi: throttling flow %s:%d %s:%d/%s because the endpoint is filtered",
		packet.SourceIPAddress(),
		packet.SourcePort(),
		packet.DestinationIPAddress(),
		packet.DestinationPort(),
		packet.TransportProtocol(),
	)
	policy := &DPIPolicy{
		Delay:   r.Delay,
		Flags:   0,
		PLR:     r.PLR,
		Spoofed: nil,
	}
	return policy, true
}
