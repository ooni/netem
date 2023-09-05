package netem

//
// DPI: rules to drop packets
//

import (
	"bytes"

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

// Filter implements DPIRule
func (r *DPIDropTrafficForServerEndpoint) Filter(
	direction DPIDirection, packet *DissectedPacket) (*DPIPolicy, bool) {
	if !packet.MatchesDestination(r.ServerProtocol, r.ServerIPAddress, r.ServerPort) {
		return nil, false
	}
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
	policy := &DPIPolicy{
		Delay:   0,
		Flags:   FrameFlagDrop,
		PLR:     0,
		Spoofed: nil,
	}
	return policy, true
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

// Filter implements DPIRule
func (r *DPIDropTrafficForTLSSNI) Filter(
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
	sni, err := packet.parseTLSServerName()
	if err != nil {
		return nil, false
	}

	// if the packet is not offending, accept it
	if sni != r.SNI {
		return nil, false
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
		Delay:   0,
		Flags:   FrameFlagDrop,
		PLR:     0,
		Spoofed: nil,
	}
	return policy, true
}

// DPIDropTrafficForString is a [DPIRule] that drops all
// the traffic after it sees a given string. The zero value is
// invalid; please fill all the fields marked as MANDATORY.
type DPIDropTrafficForString struct {
	// Logger is the MANDATORY logger
	Logger Logger

	// ServerIPAddress is the MANDATORY server endpoint IP address.
	ServerIPAddress string

	// ServerPort is the MANDATORY server endpoint port.
	ServerPort uint16

	// SNI is the MANDATORY string
	String string
}

var _ DPIRule = &DPIDropTrafficForString{}

// Filter implements DPIRule
func (r *DPIDropTrafficForString) Filter(
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

	r.Logger.Infof(
		"netem: dpi: dropping traffic for flow %s:%d %s:%d/%s because it contains %s",
		packet.SourceIPAddress(),
		packet.SourcePort(),
		packet.DestinationIPAddress(),
		packet.DestinationPort(),
		packet.TransportProtocol(),
		r.String,
	)
	policy := &DPIPolicy{
		Delay:   0,
		Flags:   FrameFlagDrop,
		PLR:     0,
		Spoofed: nil,
	}
	return policy, true
}
