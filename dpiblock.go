package netem

//
// DPI: rules to block flows
//

import (
	"github.com/google/gopacket/layers"
)

// DPIResetTrafficForTLSSNI is a [DPIRule] that sends
// a RST TCP segment after it sees a given TLS SNI. The zero value is
// invalid; please, fill all the fields marked as MANDATORY.
type DPIResetTrafficForTLSSNI struct {
	// Drop OPTIONALLY indicates you want to drop the offending Client Hello
	// as well as the rest of the traffic from this flow.
	Drop bool

	// SNI is the MANDATORY offending SNI.
	SNI string
}

var _ DPIRule = &DPIResetTrafficForTLSSNI{}

// Apply implements DPIRule
func (r *DPIResetTrafficForTLSSNI) Apply(direction DPIDirection, packet *DissectedPacket) *DPIPolicy {
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

	// prepare for sending response
	policy := &DPIPolicy{
		Verdict: 0,
		Packet:  nil,
	}

	// if possible add the packet to reflect
	rawResponse, err := reflectDissectedTCPSegmentWithRSTFlag(packet)
	if err == nil {
		policy.Verdict |= DPIVerdictInject
		policy.Packet = rawResponse
	}

	// if needed, drop traffic
	if r.Drop {
		policy.Verdict |= DPIVerdictDrop
	}
	return policy
}
