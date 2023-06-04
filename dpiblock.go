package netem

//
// DPI: rules to block flows
//

import "github.com/google/gopacket/layers"

// DPIResetTrafficForTLSSNI is a [DPIRule] that sends
// a RST TCP segment after it sees a given TLS SNI. The zero value is
// invalid; please, fill all the fields marked as MANDATORY.
//
// Note: this rule assumes that there is a router in the path that
// can generate a spoofed RST segment. If there is no router in the
// path, no RST segment will ever be generated.
type DPIResetTrafficForTLSSNI struct {
	// Logger is the MANDATORY logger.
	Logger Logger

	// SNI is the MANDATORY offending SNI.
	SNI string
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
	sni, err := packet.parseTLSServerName()
	if err != nil {
		return nil, false
	}

	// if the packet is not offending, accept it
	if sni != r.SNI {
		return nil, false
	}

	// obtain the frame to spoof
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
