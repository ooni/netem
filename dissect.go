package netem

//
// Protocol dissector
//

import (
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// DissectedPacket is a dissected IP packet. The zero-value is invalid; you
// MUST use the [dissectPacket] factory to create a new instance.
type DissectedPacket struct {
	// Packet is the underlying packet.
	Packet gopacket.Packet

	// IP is the network layer (either IPv4 or IPv6).
	IP gopacket.NetworkLayer

	// TCP is the POSSIBLY NIL tcp layer.
	TCP *layers.TCP

	// UDP is the POSSIBLY NIL UDP layer.
	UDP *layers.UDP
}

// ErrDissectShortPacket indicates the packet is too short.
var ErrDissectShortPacket = errors.New("netem: dissect: packet too short")

// ErrDissectNetwork indicates that we do not support the packet's network protocol.
var ErrDissectNetwork = errors.New("netem: dissect: unsupported network protocol")

// ErrDissectTransport indicates that we do not support the packet's transport protocol.
var ErrDissectTransport = errors.New("netem: dissect: unsupported transport protocol")

// DissectPacket parses a packet TCP/IP layers.
func DissectPacket(rawPacket []byte) (*DissectedPacket, error) {
	dp := &DissectedPacket{}

	// [UNetStack] emits raw IPv4 or IPv6 packets and we need to
	// sniff the actual version from the first octet
	if len(rawPacket) < 1 {
		return nil, ErrDissectShortPacket
	}
	version := uint8(rawPacket[0]) >> 4

	// parse the IP layer
	switch {
	case version == 4:
		dp.Packet = gopacket.NewPacket(rawPacket, layers.LayerTypeIPv4, gopacket.Lazy)
		ipLayer := dp.Packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			return nil, ErrDissectNetwork
		}
		dp.IP = ipLayer.(*layers.IPv4)

	case version == 6:
		dp.Packet = gopacket.NewPacket(rawPacket, layers.LayerTypeIPv6, gopacket.Lazy)
		ipLayer := dp.Packet.Layer(layers.LayerTypeIPv6)
		if ipLayer == nil {
			return nil, ErrDissectNetwork
		}
		dp.IP = ipLayer.(*layers.IPv6)

	default:
		return nil, ErrDissectNetwork
	}

	// parse the transport layer
	switch dp.TransportProtocol() {
	case layers.IPProtocolTCP:
		dp.TCP = dp.Packet.Layer(layers.LayerTypeTCP).(*layers.TCP)

	case layers.IPProtocolUDP:
		dp.UDP = dp.Packet.Layer(layers.LayerTypeUDP).(*layers.UDP)

	default:
		return nil, ErrDissectTransport
	}

	return dp, nil
}

// DecrementTimeToLive decrements the IPv4 or IPv6 time to live.
func (dp *DissectedPacket) DecrementTimeToLive() {
	switch v := dp.IP.(type) {
	case *layers.IPv4:
		if v.TTL > 0 {
			v.TTL--
		}
	case *layers.IPv6:
		if v.HopLimit > 0 {
			v.HopLimit--
		}
	default:
		panic(ErrDissectNetwork)
	}
}

// TimeToLive returns the packet's IPv4 or IPv6 time to live.
func (dp *DissectedPacket) TimeToLive() int64 {
	switch v := dp.IP.(type) {
	case *layers.IPv4:
		return int64(v.TTL)
	case *layers.IPv6:
		return int64(v.HopLimit)
	default:
		panic(ErrDissectNetwork)
	}
}

// DestinationIPAddress returns the packet's destination IP address.
func (dp *DissectedPacket) DestinationIPAddress() string {
	switch v := dp.IP.(type) {
	case *layers.IPv4:
		return v.DstIP.String()
	case *layers.IPv6:
		return v.DstIP.String()
	default:
		panic(ErrDissectNetwork)
	}
}

// SourceIPAddress returns the packet's source IP address.
func (dp *DissectedPacket) SourceIPAddress() string {
	switch v := dp.IP.(type) {
	case *layers.IPv4:
		return v.SrcIP.String()
	case *layers.IPv6:
		return v.SrcIP.String()
	default:
		panic(ErrDissectNetwork)
	}
}

// TransportProtocol returns the packet's transport protocol.
func (dp *DissectedPacket) TransportProtocol() layers.IPProtocol {
	switch v := dp.IP.(type) {
	case *layers.IPv4:
		return v.Protocol
	case *layers.IPv6:
		return v.NextHeader
	default:
		panic(ErrDissectNetwork)
	}
}

// Serialize serializes a previously dissected and modified packet.
func (dp *DissectedPacket) Serialize() ([]byte, error) {
	switch {
	case dp.TCP != nil:
		dp.TCP.SetNetworkLayerForChecksum(dp.IP)
	case dp.UDP != nil:
		dp.UDP.SetNetworkLayerForChecksum(dp.IP)
	default:
		return nil, ErrDissectTransport
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializePacket(buf, opts, dp.Packet); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// MatchesDestination returns true when the given IPv4 packet has the
// expected protocol, destination address, and port.
func (dp *DissectedPacket) MatchesDestination(proto layers.IPProtocol, address string, port uint16) bool {
	if dp.TransportProtocol() != proto {
		return false
	}
	switch {
	case dp.TCP != nil:
		return dp.DestinationIPAddress() == address && dp.TCP.DstPort == layers.TCPPort(port)
	case dp.UDP != nil:
		return dp.DestinationIPAddress() == address && dp.UDP.DstPort == layers.UDPPort(port)
	default:
		return false
	}
}

// MatchesSource returns true when the given IPv4 packet has the
// expected protocol, source address, and port.
func (dp *DissectedPacket) MatchesSource(proto layers.IPProtocol, address string, port uint16) bool {
	if dp.TransportProtocol() != proto {
		return false
	}
	switch {
	case dp.TCP != nil:
		return dp.SourceIPAddress() == address && dp.TCP.SrcPort == layers.TCPPort(port)
	case dp.UDP != nil:
		return dp.SourceIPAddress() == address && dp.UDP.SrcPort == layers.UDPPort(port)
	default:
		return false
	}
}
