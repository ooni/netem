package netem

//
// DPI: rules to drop packets
//

import (
	"github.com/google/gopacket/layers"
)

// DPIDropTrafficForServerEndpoint is a [DPIRule] that drops all
// the traffic towards a given server endpoint. The zero value is invalid;
// please fill all the fields marked as MANDATORY.
type DPIDropTrafficForServerEndpoint struct {
	// Logger is the MANDATORY logger
	Logger Logger

	// ServerIPAddress is the MANDATORY server endpoint IP address.
	ServerIPAddress string

	// ServerPort is the MANDATORY server endpoint port.
	ServerPort uint16

	// ServerProtocol is the MANDATORY server endpoint protocol.
	ServerProtocol layers.IPProtocol
}

var _ DPIRule = &DPIDropTrafficForServerEndpoint{}

// Apply implements DPIRule
func (r *DPIDropTrafficForServerEndpoint) Apply(direction DPIDirection, packet *DissectedPacket) *DPIPolicy {
	policy := &DPIPolicy{
		Verdict: DPIVerdictAccept,
	}
	if packet.MatchesDestination(r.ServerProtocol, r.ServerIPAddress, r.ServerPort) {
		policy.Verdict = DPIVerdictDrop
		r.Logger.Infof(
			"netem: dpi: dropping traffic for flow %s:%d %s:%d/%s because destination is %s:%d/%s",
			packet.SourceIPAddress(),
			packet.SourcePort(),
			packet.DestinationIPAddress(),
			packet.DestinationPort(),
			packet.TransportProtocol(),
			r.ServerIPAddress,
			r.ServerPort,
			r.ServerProtocol,
		)
	}
	return policy
}

// DPIDropTrafficForTLSSNI is a [DPIRule] that drops all
// the traffic after it sees a given TLS SNI. The zero value is
// invalid; please fill all the fields marked as MANDATORY.
type DPIDropTrafficForTLSSNI struct {
	// Logger is the MANDATORY logger
	Logger Logger

	// SNI is the MANDATORY SNI
	SNI string
}

var _ DPIRule = &DPIDropTrafficForTLSSNI{}

// Apply implements DPIRule
func (r *DPIDropTrafficForTLSSNI) Apply(direction DPIDirection, packet *DissectedPacket) *DPIPolicy {
	// short circuit for the return path
	if direction != DPIDirectionClientToServer {
		return &DPIPolicy{Verdict: DPIVerdictAccept}
	}

	// short circuit for UDP packets
	if packet.TransportProtocol() != layers.IPProtocolTCP {
		return &DPIPolicy{Verdict: DPIVerdictAccept}
	}

	// try to obtain the SNI
	sni, err := packet.parseTLSServerName()
	if err != nil {
		return &DPIPolicy{Verdict: DPIVerdictAccept}
	}

	// if the packet is not offending, accept it
	if sni != r.SNI {
		return &DPIPolicy{Verdict: DPIVerdictAccept}
	}

	r.Logger.Infof(
		"netem: dpi: dropping traffic for flow %s:%d %s:%d/%s because SNI==%s",
		packet.SourceIPAddress(),
		packet.SourcePort(),
		packet.DestinationIPAddress(),
		packet.DestinationPort(),
		packet.TransportProtocol(),
		sni,
	)
	policy := &DPIPolicy{
		Verdict: DPIVerdictDrop,
	}
	return policy
}
