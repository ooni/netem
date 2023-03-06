package netem

//
// DPI: rules to throttle flows
//

import (
	"github.com/google/gopacket/layers"
)

// DPIThrottleTrafficForTLSSNI is a [DPIRule] that throttles traffic
// after it sees a given TLS SNI. The zero value is not valid. Make sure
// you initialize all fields marked as MANDATORY.
type DPIThrottleTrafficForTLSSNI struct {
	// Logger is the MANDATORY logger to use.
	Logger Logger

	// PLR is the OPTIONAL extra packet loss rate to apply to the packet
	PLR float64

	// SNI is the OPTIONAL offending SNI
	SNI string
}

var _ DPIRule = &DPIThrottleTrafficForTLSSNI{}

func (r *DPIThrottleTrafficForTLSSNI) Apply(direction DPIDirection, packet *DissectedPacket) *DPIPolicy {
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
		"netem: dpi: throttling flow %s:%d %s:%d/%s because SNI==%s",
		packet.SourceIPAddress(),
		packet.SourcePort(),
		packet.DestinationIPAddress(),
		packet.DestinationPort(),
		packet.TransportProtocol(),
		sni,
	)
	policy := &DPIPolicy{
		PLR:     r.PLR,
		Verdict: DPIVerdictThrottle,
	}
	return policy
}