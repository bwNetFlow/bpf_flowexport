package bpf

import "net"

type Packet struct {
	SrcAddr       net.IP
	DstAddr       net.IP
	InIf          uint32
	OutIf         uint32
	Bytes         uint32
	Etype         uint32
	Proto         uint32
	Ipv6FlowLabel uint32
	SrcPort       uint16
	DstPort       uint16
	IPTtl         uint8
	IPTos         uint8
	IcmpType      uint8
	IcmpCode      uint8
	TcpFlags      uint8
}
