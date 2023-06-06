package netem

//
// DPI: engine
//

import (
	"sync"
	"time"

	"github.com/google/gopacket/layers"
)

// DPIDirection is the direction of packets within a
// flow according to the [DPIEngine].
type DPIDirection int

// DPIDirectionClientToServer is the direction from the
// client to the server. The client is the endpoint that
// sends the first packet in a flow.
const DPIDirectionClientToServer = DPIDirection(0)

// DPIDirectionServerToClient is the direction from the
// server to the client. The client is the endpoint that
// sends the first packet in a flow.
const DPIDirectionServerToClient = DPIDirection(1)

// DPIPolicy tells the [DPIEngine] which policy to apply to a packet.
type DPIPolicy struct {
	// Delay is the extra delay to add to the packet.
	Delay time.Duration

	// Flags contains the flags to apply to the packet [Frame].
	Flags int64

	// PLR is the extra PLR to add to the packet.
	PLR float64

	// Spoofed contains the spoofed frames to attach to
	// the [Frame] so that we emit spoofed packets in the
	// router when the frame is being processed.
	Spoofed [][]byte
}

// DPIRule is a deep packet inspection rule.
type DPIRule interface {
	Filter(direction DPIDirection, packet *DissectedPacket) (*DPIPolicy, bool)
}

// DPIEngine is a deep packet inspection engine. The zero
// value is invalid; construct using [NewDPIEngine].
type DPIEngine struct {
	// flows contains information about flows.
	flows map[uint64]*dpiFlow

	// logger is the logger.
	logger Logger

	// mu provides mutual exclusion.
	mu sync.Mutex

	// rules contains the rules.
	rules []DPIRule
}

// NewDPIEngine creates a new [DPIEngine] instance.
func NewDPIEngine(logger Logger) *DPIEngine {
	return &DPIEngine{
		flows:  map[uint64]*dpiFlow{},
		logger: logger,
		mu:     sync.Mutex{},
		rules:  nil,
	}
}

// AddRule adds a [DPIRule] to the [DPIEngine].
func (de *DPIEngine) AddRule(rule DPIRule) {
	defer de.mu.Unlock()
	de.mu.Lock()
	de.rules = append(de.rules, rule)
}

// getRulesShallowCopy returns a shallow copy of the rules.
func (de *DPIEngine) getRulesShallowCopy() []DPIRule {
	defer de.mu.Unlock()
	de.mu.Lock()
	return append([]DPIRule{}, de.rules...) // copy
}

// inspect applies DPI to an IP packet.
func (de *DPIEngine) inspect(rawPacket []byte) (*DPIPolicy, bool) {
	// dissect the packet and drop packets we don't recognize.
	packet, err := DissectPacket(rawPacket)
	if err != nil {
		return nil, false
	}

	// obtain flow
	flow := de.getFlow(packet)

	// lock the flow record while we're processing it
	defer flow.mu.Unlock()
	flow.mu.Lock()

	// increment number of seen packets
	flow.numPackets++

	// if we have already computed a policy, just use it
	if flow.policy != nil {
		return flow.policy, true
	}

	// avoid inspecting too many flow packets
	const maxPackets = 10
	if flow.numPackets >= maxPackets {
		return nil, false
	}

	// compute direction
	direction := flow.directionLocked(packet)

	// execute all the rules and stop at the first non-accept result
	for _, rule := range de.getRulesShallowCopy() {
		policy, match := rule.Filter(direction, packet)
		if match {
			flow.policy = policy // remember the policy
			return policy, true
		}
	}

	return nil, false
}

// getFlow returns the flow associated with this packet.
func (de *DPIEngine) getFlow(packet *DissectedPacket) *dpiFlow {
	defer de.mu.Unlock()
	de.mu.Lock()

	// when a flow has not been modified in 30 seconds, we assume that
	// the record is now stale and we create a new record
	const maxSilence = 30 * time.Second
	fh := packet.FlowHash()
	flow := de.flows[fh]
	if flow == nil || time.Since(flow.updated) > maxSilence {
		flow = newDPIFlow(packet)
		de.flows[fh] = flow
	}
	flow.updated = time.Now()

	return flow
}

// dpiFlow is a TCP/UDP flow tracked by DPI.
type dpiFlow struct {
	// destIP is the dest IP address.
	destIP string

	// destPort is the dest port.
	destPort uint16

	// mu provides mutual exclusion.
	mu sync.Mutex

	// numPackets is the number of packets we inspected in either direction.
	numPackets int64

	// policy is the policy we previously evaluated or nil.
	policy *DPIPolicy

	// protocol is the protocol used by the flow.
	protocol layers.IPProtocol

	// sourceIP is the source IP address.
	sourceIP string

	// sourcePort is the source port.
	sourcePort uint16

	// updated is the last time this flow was updated.
	updated time.Time
}

// newDPIFlow creates a new [dpiFlow] instance.
func newDPIFlow(packet *DissectedPacket) *dpiFlow {
	return &dpiFlow{
		destIP:     packet.DestinationIPAddress(),
		destPort:   packet.DestinationPort(),
		mu:         sync.Mutex{},
		numPackets: 0,
		policy:     nil,
		protocol:   packet.TransportProtocol(),
		sourceIP:   packet.SourceIPAddress(),
		sourcePort: packet.SourcePort(),
		updated:    time.Now(),
	}
}

// directionLocked returns the flow direction
func (df *dpiFlow) directionLocked(packet *DissectedPacket) DPIDirection {
	if packet.MatchesDestination(df.protocol, df.destIP, df.destPort) {
		return DPIDirectionClientToServer
	}
	return DPIDirectionServerToClient
}
