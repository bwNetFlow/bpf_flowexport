package bpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"syscall"

	"github.com/iovisor/gobpf/bcc"
)

/*
#cgo LDFLAGS: -lbcc
#include <bcc/libbpf.h>
*/
import "C"

const source string = `#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <bcc/proto.h>

#define ICMP 	1
#define TCP 	6
#define UDP 	17
#define ICMPv6 	58

typedef struct {
    unsigned long long  src_hi;
    unsigned long long  src_lo;
    unsigned long long  dst_hi;
    unsigned long long  dst_lo;
    __u32 ingress_iface;
    __u32 collect_iface;
    __u32 bytes;
    __u32 etype;
    __u32 proto;
    __u32 ipv6_flowlabel;
    __u32 srcaddr;
    __u32 dstaddr;
    __u16 srcport;
    __u16 dstport;
    __u8 ipttl;
    __u8 tos;
    __u8 icmp_type;
    __u8 icmp_code;
    __u8 tcp_flags;
} packet_event_t;
BPF_PERF_OUTPUT(packet_events);

int packet_dump(struct __sk_buff *skb) {

    packet_event_t pkt = {};
    u8 *cursor = 0;


    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    if (!(ethernet->type == ETH_P_IP || ethernet->type == ETH_P_IPV6)) {
        return -1;
    }

    pkt.etype = ethernet->type;

    // TODO: this is the in interface, either 0 (local originated) or the
    // configured 'listening' iface, depending on the packets direction. Can we
    // get the out interface if this linux is running with ip_forward?
    // What does this report on a bridge?
    pkt.ingress_iface = skb->ingress_ifindex;
    pkt.collect_iface = skb->ifindex;

    if (ethernet->type == ETH_P_IP) {
        struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
        pkt.bytes = ip->hlen + ip->tlen;
        pkt.proto = ip->nextp;
        pkt.srcaddr = ip->src;
        pkt.dstaddr = ip->dst;
        pkt.ipttl = ip->ttl;
        pkt.tos = ip->tos;
        if (ip->nextp == TCP) {
            struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));
            pkt.srcport = tcp->src_port;
            pkt.dstport = tcp->dst_port;
            pkt.tcp_flags = tcp->flag_cwr << 7;
            pkt.tcp_flags = pkt.tcp_flags | tcp->flag_ece << 6;
            pkt.tcp_flags = pkt.tcp_flags | tcp->flag_urg << 5;
            pkt.tcp_flags = pkt.tcp_flags | tcp->flag_ack << 4;
            pkt.tcp_flags = pkt.tcp_flags | tcp->flag_psh << 3;
            pkt.tcp_flags = pkt.tcp_flags | tcp->flag_rst << 2;
            pkt.tcp_flags = pkt.tcp_flags | tcp->flag_syn << 1;
            pkt.tcp_flags = pkt.tcp_flags | tcp->flag_fin;
        } else if (ip->nextp == UDP) {
            struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));
            pkt.srcport = udp->sport;
            pkt.dstport = udp->dport;
        } else if (ip->nextp == ICMP) {
            struct icmp_t *icmp = cursor_advance(cursor, sizeof(*icmp));
            pkt.icmp_type = icmp->type;
            pkt.icmp_code = icmp->code;
        }
    } else if (ethernet->type == ETH_P_IPV6) {
        struct ip6_t *ip6 = cursor_advance(cursor, sizeof(*ip6));
        pkt.bytes = 40 + ip6->payload_len;
        pkt.proto = ip6->next_header;
        pkt.ipv6_flowlabel = ip6->flow_label;
        pkt.src_hi = ip6->src_hi;
        pkt.src_lo = ip6->src_lo;
        pkt.dst_hi = ip6->dst_hi;
        pkt.dst_lo = ip6->dst_lo;
        pkt.ipttl = ip6->hop_limit;
        pkt.tos = ip6->priority;
        if (ip6->next_header == TCP) {
            struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));
            pkt.srcport = tcp->src_port;
            pkt.dstport = tcp->dst_port;
            pkt.tcp_flags = tcp->flag_cwr << 7;
            pkt.tcp_flags = pkt.tcp_flags | tcp->flag_ece << 6;
            pkt.tcp_flags = pkt.tcp_flags | tcp->flag_urg << 5;
            pkt.tcp_flags = pkt.tcp_flags | tcp->flag_ack << 4;
            pkt.tcp_flags = pkt.tcp_flags | tcp->flag_psh << 3;
            pkt.tcp_flags = pkt.tcp_flags | tcp->flag_rst << 2;
            pkt.tcp_flags = pkt.tcp_flags | tcp->flag_syn << 1;
            pkt.tcp_flags = pkt.tcp_flags | tcp->flag_fin;
        } else if (ip6->next_header == UDP) {
            struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));
            pkt.srcport = udp->sport;
            pkt.dstport = udp->dport;
        } else if (ip6->next_header == ICMPv6) {
            struct icmp6_t *icmp6 = cursor_advance(cursor, sizeof(*icmp6));
            pkt.icmp_type = icmp6->type;
            pkt.icmp_code = icmp6->code;
        }
    }


    packet_events.perf_submit(skb, &pkt, sizeof(pkt));

    return -1;
}
`

type rawPacket struct {
	SrcAddrHi     uint64
	SrcAddrLo     uint64
	DstAddrHi     uint64
	DstAddrLo     uint64
	IngressIface  uint32
	CollectIface  uint32
	Bytes         uint32
	Etype         uint32
	Proto         uint32
	Ipv6FlowLabel uint32
	SrcAddr       uint32
	DstAddr       uint32
	SrcPort       uint16
	DstPort       uint16
	IPTtl         uint8
	IPTos         uint8
	IcmpType      uint8
	IcmpCode      uint8
	TcpFlags      uint8
}

func parseRawPacket(rawPacket rawPacket) Packet {
	var srcip, dstip net.IP
	if rawPacket.Etype == 0x0800 {
		srcip = make(net.IP, 4)
		binary.BigEndian.PutUint32(srcip, rawPacket.SrcAddr)
		dstip = make(net.IP, 4)
		binary.BigEndian.PutUint32(dstip, rawPacket.DstAddr)
	} else if rawPacket.Etype == 0x86dd {
		srcip = make(net.IP, 16)
		binary.BigEndian.PutUint64(srcip, rawPacket.SrcAddrHi)
		binary.BigEndian.PutUint64(srcip[8:], rawPacket.SrcAddrLo)
		dstip = make(net.IP, 16)
		binary.BigEndian.PutUint64(dstip, rawPacket.DstAddrHi)
		binary.BigEndian.PutUint64(dstip[8:], rawPacket.DstAddrLo)
	}
	return Packet{SrcAddr: srcip,
		DstAddr:       dstip,
		IngressIface:  rawPacket.IngressIface,
		CollectIface:  rawPacket.CollectIface,
		Bytes:         rawPacket.Bytes,
		Etype:         rawPacket.Etype,
		Proto:         rawPacket.Proto,
		Ipv6FlowLabel: rawPacket.Ipv6FlowLabel,
		SrcPort:       rawPacket.SrcPort,
		DstPort:       rawPacket.DstPort,
		IPTtl:         rawPacket.IPTtl,
		IPTos:         rawPacket.IPTos,
		IcmpType:      rawPacket.IcmpType,
		IcmpCode:      rawPacket.IcmpCode,
		TcpFlags:      rawPacket.TcpFlags,
	}
}

type PacketDumper struct {
	rawData        chan []byte
	decoderRunning bool
	packets        chan Packet // exported through .Packets()

	// setup
	module         *bcc.Module
	socketFilterFd int
	iface          *net.Interface

	// start
	socketFd int
	perfMap  *bcc.PerfMap
}

func (b *PacketDumper) Packets() chan Packet {
	if b.decoderRunning {
		return b.packets
	}
	b.decoderRunning = true
	b.packets = make(chan Packet)
	go func() {
		var rawPacket rawPacket
		for data := range b.rawData {
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &rawPacket)
			if err != nil {
				log.Printf("BpfDump: Failed to decode received data: %s\n", err)
				continue
			}
			b.packets <- parseRawPacket(rawPacket)
		}
	}()
	return b.packets
}

func (b *PacketDumper) Setup(device string) error {
	b.module = bcc.NewModule(source, []string{}) // compiling C here

	var err error
	if b.socketFilterFd, err = b.module.Load("packet_dump", C.BPF_PROG_TYPE_SOCKET_FILTER, 0, 0); err != nil {
		return fmt.Errorf("Unable to find socket filter packet_dump, err: %v", err)
	}

	if b.iface, err = net.InterfaceByName(device); err != nil {
		return fmt.Errorf("Unable to get interface, err: %v", err)
	}

	return nil
}

func (b *PacketDumper) Start() error {
	var err error
	// 768 is the network byte order representation of 0x3 (constant syscall.ETH_P_ALL)
	if b.socketFd, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, 768); err != nil {
		return fmt.Errorf("Unable to open raw socket, err: %v", err)
	}

	sll := syscall.SockaddrLinklayer{
		Ifindex:  b.iface.Index,
		Protocol: 768,
	}
	if err := syscall.Bind(b.socketFd, &sll); err != nil {
		return fmt.Errorf("Unable to bind interface to raw socket, err: %v", err)
	}

	if ret, err := C.bpf_attach_socket(C.int(b.socketFd), C.int(b.socketFilterFd)); ret != 0 {
		return fmt.Errorf("Unable to attach BPF socket filter: %v", err)
	}

	b.rawData = make(chan []byte)
	packettable := bcc.NewTable(b.module.TableId("packet_events"), b.module)
	if b.perfMap, err = bcc.InitPerfMap(packettable, b.rawData, nil); err != nil {
		return fmt.Errorf("Unable to init perf map: %v", err)
	}

	b.perfMap.Start()
	return nil
}

func (b *PacketDumper) Stop() {
	b.module.Close()
	syscall.Close(b.socketFd)
	b.perfMap.Stop()
}
