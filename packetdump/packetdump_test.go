//go:build linux

package packetdump

import (
	"encoding/binary"
	"net"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
)

// Offsets of the packet_t fields in bpf/bpf.c, manually written so the test
// has a generated bpfPacketT that deviates.
const (
	offsetSrcHi         = 0
	offsetSrcLo         = 8
	offsetDstHi         = 16
	offsetDstLo         = 24
	offsetInif          = 32
	offsetOutif         = 36
	offsetBytes         = 40
	offsetEtype         = 44
	offsetProto         = 48
	offsetIpv6Flowlabel = 52
	offsetSrcaddr       = 56
	offsetDstaddr       = 60
	offsetSrcport       = 64
	offsetDstport       = 66
	offsetIpttl         = 68
	offsetTos           = 69
	offsetIcmpType      = 70
	offsetIcmpCode      = 71
	offsetTcpFlags      = 72
	offsetDirection     = 73
	offsetRemoteaddr    = 74
	packetSize          = 80
)

type sample []byte

func newSample() sample { return make(sample, packetSize) }

func (raw sample) u64(offset int, value uint64) sample {
	binary.NativeEndian.PutUint64(raw[offset:], value)
	return raw
}

func (raw sample) u32(offset int, value uint32) sample {
	binary.NativeEndian.PutUint32(raw[offset:], value)
	return raw
}

func (raw sample) u16(offset int, value uint16) sample {
	binary.NativeEndian.PutUint16(raw[offset:], value)
	return raw
}

func (raw sample) u8(offset int, value uint8) sample {
	raw[offset] = value
	return raw
}

func sameByteOrder(first, second binary.ByteOrder) bool {
	probe := []byte{1, 2}
	return first.Uint16(probe) == second.Uint16(probe)
}

// cilium/ebpf reports binary.LittleEndian or binary.BigEndian, which never compare
// equal to binary.NativeEndian
func TestByteOrder(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Programs) == 0 {
		t.Fatal("collection spec has no programs")
	}
	for name, prog := range spec.Programs {
		if !sameByteOrder(prog.ByteOrder, binary.NativeEndian) {
			t.Errorf("program %s: byte order %v does not match the host", name, prog.ByteOrder)
		}
		if prog.Type != ebpf.SocketFilter {
			t.Errorf("program %s: type %v, want %v", name, prog.Type, ebpf.SocketFilter)
		}
	}
}

func TestPacketLayoutSize(t *testing.T) {
	if size := binary.Size(bpfPacketT{}); size != packetSize {
		t.Fatalf("bpfPacketT is %d bytes, packet_t is %d", size, packetSize)
	}
}

func TestDecodePacket(t *testing.T) {
	cases := []struct {
		name   string
		raw    sample
		packet Packet
	}{
		{
			name: "ipv4 tcp",
			raw: newSample().
				u32(offsetInif, 3).
				u32(offsetBytes, 1500).
				u32(offsetEtype, 0x0800).
				u32(offsetProto, 6).
				u32(offsetSrcaddr, 0xc0000201).
				u32(offsetDstaddr, 0xc6336401).
				u16(offsetSrcport, 443).
				u16(offsetDstport, 51234).
				u8(offsetIpttl, 57).
				u8(offsetTos, 0x28).
				u8(offsetTcpFlags, 0x12).
				u8(offsetDirection, 0).
				u8(offsetRemoteaddr, 1),
			packet: Packet{
				SrcAddr:       net.ParseIP("10.10.10.1").To4(),
				DstAddr:       net.ParseIP("10.10.10.2").To4(),
				InIf:          3,
				Bytes:         1500,
				Etype:         0x0800,
				Proto:         6,
				SrcPort:       443,
				DstPort:       51234,
				IPTtl:         57,
				IPTos:         0x28,
				TcpFlags:      0x12,
				FlowDirection: 0,
				RemoteAddr:    1,
			},
		},
		{
			name: "ipv6 udp",
			raw: newSample().
				u64(offsetSrcHi, 0x20010db800000000).
				u64(offsetSrcLo, 0x0000000000000001).
				u64(offsetDstHi, 0x20010db8ffff0000).
				u64(offsetDstLo, 0x00000000000000fe).
				u32(offsetOutif, 7).
				u32(offsetBytes, 1280).
				u32(offsetEtype, 0x86dd).
				u32(offsetProto, 17).
				u32(offsetIpv6Flowlabel, 0xabcde).
				u16(offsetSrcport, 5353).
				u16(offsetDstport, 53).
				u8(offsetIpttl, 255).
				u8(offsetTos, 0xb8).
				u8(offsetDirection, 1).
				u8(offsetRemoteaddr, 2),
			packet: Packet{
				SrcAddr:       net.ParseIP("2001:db8::1"),
				DstAddr:       net.ParseIP("2001:db8:ffff::fe"),
				OutIf:         7,
				Bytes:         1280,
				Etype:         0x86dd,
				Proto:         17,
				Ipv6FlowLabel: 0xabcde,
				SrcPort:       5353,
				DstPort:       53,
				IPTtl:         255,
				IPTos:         0xb8,
				FlowDirection: 1,
				RemoteAddr:    2,
			},
		},
		{
			name: "icmp",
			raw: newSample().
				u32(offsetEtype, 0x0800).
				u32(offsetProto, 1).
				u32(offsetSrcaddr, 0x7f000001).
				u32(offsetDstaddr, 0x7f000001).
				u8(offsetIcmpType, 3).
				u8(offsetIcmpCode, 13),
			packet: Packet{
				SrcAddr:  net.ParseIP("127.0.0.1").To4(),
				DstAddr:  net.ParseIP("127.0.0.1").To4(),
				Etype:    0x0800,
				Proto:    1,
				IcmpType: 3,
				IcmpCode: 13,
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			packet, err := decodePacket(testCase.raw)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(packet, testCase.packet) {
				t.Errorf("decoded\n%+v\nwant\n%+v", packet, testCase.packet)
			}
		})
	}
}

func TestTruncat(t *testing.T) {
	if _, err := decodePacket(newSample()[:packetSize-1]); err == nil {
		t.Fatal("expected an error for a truncated sample")
	}
}

func TestHtons(t *testing.T) {
	var buf [2]byte
	binary.NativeEndian.PutUint16(buf[:], htons(0x0003))
	if buf != [2]byte{0x00, 0x03} {
		t.Fatalf("htons(0x0003) is stored as %#v, want network byte order", buf)
	}
}

func TestSamplerAddress(t *testing.T) {
	ipnet := func(cidr string) net.Addr {
		ip, network, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatal(err)
		}
		network.IP = ip
		return network
	}

	cases := []struct {
		name  string
		addrs []net.Addr
		want  net.IP
	}{
		{"global > link-local", []net.Addr{ipnet("fe80::1/64"), ipnet("2001:db8::2/64")}, net.ParseIP("2001:db8::2")},
		{"link-local as fallback", []net.Addr{ipnet("::1/128"), ipnet("fe80::1/64")}, net.ParseIP("fe80::1")},
		{"loopback only", []net.Addr{ipnet("127.0.0.1/8")}, nil},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := pickSamplerAddress(testCase.addrs); !got.Equal(testCase.want) {
				t.Errorf("got %v, want %v", got, testCase.want)
			}
		})
	}
}
