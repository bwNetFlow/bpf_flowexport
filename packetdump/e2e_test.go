//go:build linux

package packetdump

import (
	"encoding/binary"
	"net"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const injectedTTL = 42 //use custom TTL to check if package is from test

func ipv4Header(proto uint8, tos uint8, fragmentOffset uint16, src, dst string, payloadLen int) []byte {
	header := make([]byte, 20)
	header[0] = 0x45
	header[1] = tos
	binary.BigEndian.PutUint16(header[2:], uint16(len(header)+payloadLen))
	binary.BigEndian.PutUint16(header[6:], fragmentOffset)
	header[8] = injectedTTL
	header[9] = proto
	copy(header[12:], net.ParseIP(src).To4())
	copy(header[16:], net.ParseIP(dst).To4())
	return header
}

func ipv6Header(nextHeader uint8, trafficClass uint8, flowLabel uint32, src, dst string, payloadLen int) []byte {
	header := make([]byte, 40)
	binary.BigEndian.PutUint32(header, 6<<28|uint32(trafficClass)<<20|flowLabel)
	binary.BigEndian.PutUint16(header[4:], uint16(payloadLen))
	header[6] = nextHeader
	header[7] = injectedTTL
	copy(header[8:], net.ParseIP(src).To16())
	copy(header[24:], net.ParseIP(dst).To16())
	return header
}

func tcpHeader(srcPort, dstPort uint16, flags uint8) []byte {
	header := make([]byte, 20)
	binary.BigEndian.PutUint16(header, srcPort)
	binary.BigEndian.PutUint16(header[2:], dstPort)
	header[12] = 5 << 4
	header[13] = flags
	return header
}

func udpHeader(srcPort, dstPort uint16, payloadLen int) []byte {
	header := make([]byte, 8)
	binary.BigEndian.PutUint16(header, srcPort)
	binary.BigEndian.PutUint16(header[2:], dstPort)
	binary.BigEndian.PutUint16(header[4:], uint16(len(header)+payloadLen))
	return header
}

func icmpEcho(icmpType uint8) []byte {
	return []byte{icmpType, 0, 0, 0, 0x12, 0x34, 0, 1}
}

func concat(parts ...[]byte) []byte {
	var joined []byte
	for _, part := range parts {
		joined = append(joined, part...)
	}
	return joined
}

func ipv4Packet(proto uint8, tos uint8, fragmentOffset uint16, src, dst string, payload []byte) []byte {
	return concat(ipv4Header(proto, tos, fragmentOffset, src, dst, len(payload)), payload)
}

func ipv6Packet(nextHeader uint8, trafficClass uint8, flowLabel uint32, src, dst string, payload []byte) []byte {
	return concat(ipv6Header(nextHeader, trafficClass, flowLabel, src, dst, len(payload)), payload)
}

func inject(t *testing.T, ifindex int, etype uint16, l3packet []byte) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)

	frame := make([]byte, 14)
	binary.BigEndian.PutUint16(frame[12:], etype)
	frame = append(frame, l3packet...)
	addr := unix.SockaddrLinklayer{Ifindex: ifindex, Protocol: htons(etype)}
	if err := unix.Sendto(fd, frame, 0, &addr); err != nil {
		t.Fatal(err)
	}
}

// awaitBothCopies returns the egress and ingress copy of the next injected packet.
func awaitBothCopies(t *testing.T, packets chan Packet) (Packet, Packet) {
	t.Helper()
	var egress, ingress *Packet
	timeout := time.After(3 * time.Second)
	for egress == nil || ingress == nil {
		select {
		case packet := <-packets:
			if packet.IPTtl != injectedTTL {
				continue
			}
			if packet.FlowDirection == 1 {
				egress = &packet
			} else {
				ingress = &packet
			}
		case <-timeout:
			t.Fatalf("timed out waiting for injected packet (egress seen: %v, ingress seen: %v)", egress != nil, ingress != nil)
		}
	}
	return *egress, *ingress
}

func hasCapability(data [2]unix.CapUserData, capability int) bool {
	return data[capability/32].Effective&(1<<(capability%32)) != 0
}

func canCapture() bool {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&header, &data[0]); err != nil {
		return false
	}
	canLoad := hasCapability(data, unix.CAP_SYS_ADMIN) ||
		(hasCapability(data, unix.CAP_BPF) && hasCapability(data, unix.CAP_PERFMON))
	return canLoad && hasCapability(data, unix.CAP_NET_RAW)
}

func TestEndToEndLoopback(t *testing.T) {
	if !canCapture() {
		t.Skip("unable to caputure with current capabilities")
	}

	loopback, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}

	dumper := &PacketDumper{}
	if err := dumper.Setup("lo"); err != nil {
		t.Fatal(err)
	}
	if err := dumper.Start(); err != nil {
		dumper.Stop()
		t.Fatal(err)
	}
	packets := dumper.Packets()
	t.Cleanup(func() {
		if err := dumper.Stop(); err != nil {
			t.Error(err)
		}
		for range packets {
		}
	})

	payload := []byte("data")
	hopByHop := []byte{unix.IPPROTO_TCP, 0, 1, 4, 0, 0, 0, 0}
	nonFirstFragment := uint16(100)

	cases := []struct {
		name   string
		etype  uint16
		packet []byte
		want   Packet
	}{
		{
			name:   "ipv4 tcp",
			etype:  unix.ETH_P_IP,
			packet: ipv4Packet(unix.IPPROTO_TCP, 0x28, 0, "127.0.0.11", "127.0.0.1", tcpHeader(40001, 40002, 0x02)),
			want: Packet{
				SrcAddr: net.ParseIP("127.0.0.11").To4(), DstAddr: net.ParseIP("127.0.0.1").To4(),
				Bytes: 40, Etype: unix.ETH_P_IP, Proto: unix.IPPROTO_TCP,
				SrcPort: 40001, DstPort: 40002, IPTtl: injectedTTL, IPTos: 0x28, TcpFlags: 0x02,
			},
		},
		{
			name:   "ipv4 udp",
			etype:  unix.ETH_P_IP,
			packet: ipv4Packet(unix.IPPROTO_UDP, 0, 0, "127.0.0.12", "127.0.0.1", concat(udpHeader(40003, 40004, len(payload)), payload)),
			want: Packet{
				SrcAddr: net.ParseIP("127.0.0.12").To4(), DstAddr: net.ParseIP("127.0.0.1").To4(),
				Bytes: 32, Etype: unix.ETH_P_IP, Proto: unix.IPPROTO_UDP,
				SrcPort: 40003, DstPort: 40004, IPTtl: injectedTTL,
			},
		},
		{
			name:   "ipv4 icmp",
			etype:  unix.ETH_P_IP,
			packet: ipv4Packet(unix.IPPROTO_ICMP, 0, 0, "127.0.0.13", "127.0.0.1", icmpEcho(8)),
			want: Packet{
				SrcAddr: net.ParseIP("127.0.0.13").To4(), DstAddr: net.ParseIP("127.0.0.1").To4(),
				Bytes: 28, Etype: unix.ETH_P_IP, Proto: unix.IPPROTO_ICMP,
				IPTtl: injectedTTL, IcmpType: 8,
			},
		},
		{
			name:   "ipv4 non-first fragment skips l4",
			etype:  unix.ETH_P_IP,
			packet: ipv4Packet(unix.IPPROTO_UDP, 0, nonFirstFragment, "127.0.0.14", "127.0.0.1", udpHeader(40005, 40006, 0)),
			want: Packet{
				SrcAddr: net.ParseIP("127.0.0.14").To4(), DstAddr: net.ParseIP("127.0.0.1").To4(),
				Bytes: 28, Etype: unix.ETH_P_IP, Proto: unix.IPPROTO_UDP, IPTtl: injectedTTL,
			},
		},
		{
			name:   "ipv6 tcp with traffic class and flow label",
			etype:  unix.ETH_P_IPV6,
			packet: ipv6Packet(unix.IPPROTO_TCP, 0xb8, 0x12345, "::1", "::1", tcpHeader(40007, 40008, 0x12)),
			want: Packet{
				SrcAddr: net.ParseIP("::1"), DstAddr: net.ParseIP("::1"),
				Bytes: 60, Etype: unix.ETH_P_IPV6, Proto: unix.IPPROTO_TCP, Ipv6FlowLabel: 0x12345,
				SrcPort: 40007, DstPort: 40008, IPTtl: injectedTTL, IPTos: 0xb8, TcpFlags: 0x12,
			},
		},
		{
			name:   "ipv6 icmpv6",
			etype:  unix.ETH_P_IPV6,
			packet: ipv6Packet(unix.IPPROTO_ICMPV6, 0, 0, "::1", "::1", icmpEcho(128)),
			want: Packet{
				SrcAddr: net.ParseIP("::1"), DstAddr: net.ParseIP("::1"),
				Bytes: 48, Etype: unix.ETH_P_IPV6, Proto: unix.IPPROTO_ICMPV6,
				IPTtl: injectedTTL, IcmpType: 128,
			},
		},
		{
			name:   "ipv6 hop-by-hop then tcp",
			etype:  unix.ETH_P_IPV6,
			packet: ipv6Packet(unix.IPPROTO_HOPOPTS, 0, 0, "::1", "::1", concat(hopByHop, tcpHeader(40009, 40010, 0x10))),
			want: Packet{
				SrcAddr: net.ParseIP("::1"), DstAddr: net.ParseIP("::1"),
				Bytes: 68, Etype: unix.ETH_P_IPV6, Proto: unix.IPPROTO_TCP,
				SrcPort: 40009, DstPort: 40010, IPTtl: injectedTTL, TcpFlags: 0x10,
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			inject(t, loopback.Index, testCase.etype, testCase.packet)
			egress, ingress := awaitBothCopies(t, packets)

			wantEgress := testCase.want
			wantEgress.OutIf = uint32(loopback.Index)
			wantEgress.FlowDirection = 1
			wantEgress.RemoteAddr = 2
			if !reflect.DeepEqual(egress, wantEgress) {
				t.Errorf("egress copy\n%+v\nwant\n%+v", egress, wantEgress)
			}

			wantIngress := testCase.want
			wantIngress.InIf = uint32(loopback.Index)
			wantIngress.FlowDirection = 0
			wantIngress.RemoteAddr = 1
			if !reflect.DeepEqual(ingress, wantIngress) {
				t.Errorf("ingress copy\n%+v\nwant\n%+v", ingress, wantIngress)
			}
		})
	}
}
