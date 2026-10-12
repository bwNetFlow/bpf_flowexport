#include <linux/types.h> // __u* types

#include <linux/bpf.h> // BPF constants
#include <bpf/bpf_helpers.h> // SEC macro
#include <bpf/bpf_endian.h> // bpf_ntoh*

#include <linux/if_packet.h> // PACKET_*
#include <linux/if_ether.h> // ETH_*
#include <linux/ip.h> // iphdr
#include <linux/in.h> // IPPROTO_*
#include <linux/ipv6.h> // ip6hdr
#include <linux/udp.h> // udphdr
#include <linux/tcp.h> // tcphdr

#define IPV6_MAX_EXT_HEADERS 4

#pragma pack(push, 1)
typedef struct {
  __u8  ver_ihl;
  __u8  tos;
  __u16 total_length;
  __u16 id;
  __u16 flags_fo;
  __u8  ttl;
  __u8  protocol;
  __u16 checksum;
  __u32 srcaddr;
  __u32 dstaddr;
} ip4_header_t;

typedef struct {
  __u32 ver_tc_fl;
  __u16 payload_length;
  __u8  next_header;
  __u8  hop_limit;
  __u64 src_hi;
  __u64 src_lo;
  __u64 dst_hi;
  __u64 dst_lo;
} ip6_header_t;

typedef struct {
  __u8  next_header;
  __u8  hdr_ext_len;
  __u16 frag_off; // only meaningful in a fragment header
  // remainder does not matter
} ip6_ext_header_t;

typedef struct {
  __u16 srcport;
  __u16 dstport;
  __u32 seq;
  __u32 ack;
  __u8  data_offset; // and 4 extra bits
  __u8  flags;
  // remainder does not matter
} tcp_header_t;

typedef struct {
  __u16 srcport;
  __u16 dstport;
  // remainder does not matter
} udp_header_t;

typedef struct {
  __u8 type;
  __u8 code;
} icmp_header_t;
#pragma pack(pop)

typedef struct {
    __u64 src_hi; // L3
    __u64 src_lo; // L3
    __u64 dst_hi; // L3
    __u64 dst_lo; // L3
    __u32 inif; // L1
    __u32 outif; // L1
    __u32 bytes; // len(L3 packet), IP header included
    __u32 etype; // L2
    __u32 proto; // L3, for IPv6 the protocol after any extension headers
    __u32 ipv6_flowlabel; // L3
    __u32 srcaddr; // L3
    __u32 dstaddr; // L3
    __u16 srcport; // L4
    __u16 dstport; // L4
    __u8 ipttl; // L3
    __u8 tos; // L3
    __u8 icmp_type; // L4
    __u8 icmp_code; // L4
    __u8 tcp_flags; // L4
    __u8 direction; // L1
    __u8 remoteaddr; // L1
} packet_t;

// Locals don't end up in BTF; bpf2go -type packet_t needs the type referenced from a global.
const packet_t *unused_packet_t __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} packets SEC(".maps");

static __always_inline int is_ipv6_ext_header(__u8 next_header) {
    return next_header == IPPROTO_HOPOPTS || next_header == IPPROTO_ROUTING ||
           next_header == IPPROTO_FRAGMENT || next_header == IPPROTO_DSTOPTS ||
           next_header == IPPROTO_AH;
}

SEC("socket")
int packet_dump(struct __sk_buff *skb) {

    packet_t pkt = {};

    // L1
    //
    pkt.inif = skb->ingress_ifindex;
    switch (skb->pkt_type) {
    case PACKET_OUTGOING: // from us
        pkt.direction = 1; // egress
        pkt.remoteaddr = 2; // remote address is dstaddr
        pkt.outif = skb->ifindex; // since it's egress, we're the outif
        break;
    case PACKET_HOST: // to us
    case PACKET_BROADCAST:
    case PACKET_MULTICAST:
        pkt.direction = 0; // ingress
        pkt.remoteaddr = 1; // remote address is srcaddr
        pkt.outif = 0; // we don't have any info without our fib
        break;
    default: // PACKET_OTHERHOST, seen in promiscuous mode: transit traffic, neither address is ours
        pkt.direction = 0; // ingress
        pkt.remoteaddr = 0; // neither
        pkt.outif = 0;
        break;
    }

    // L2
    pkt.etype = bpf_ntohs(skb->protocol);

    // L3
    // Loads are relative to the network header so devices without a MAC header (tun, wg, ppp) work too.
    // A packet whose L3 header can't be loaded is skipped.
    __u32 l4_offset;
    int parse_l4 = 1;
    if (pkt.etype == ETH_P_IP) {
        ip4_header_t ip_header;
        if (bpf_skb_load_bytes_relative(skb, 0, &ip_header, sizeof(ip_header), BPF_HDR_START_NET) < 0) {
            return 0;
        }

        l4_offset = 4 * (ip_header.ver_ihl & 0x0f);
        if (l4_offset < sizeof(ip_header)) {
            return 0;
        }

        pkt.bytes = bpf_ntohs(ip_header.total_length);
        pkt.proto = ip_header.protocol;
        pkt.tos = ip_header.tos;
        pkt.ipttl = ip_header.ttl;
        pkt.srcaddr = bpf_ntohl(ip_header.srcaddr);
        pkt.dstaddr = bpf_ntohl(ip_header.dstaddr);

        if ((bpf_ntohs(ip_header.flags_fo) & 0x1fff) != 0) { // non-first fragment, no L4 header
            parse_l4 = 0;
        }
    } else if (pkt.etype == ETH_P_IPV6) {
        ip6_header_t ip_header;
        if (bpf_skb_load_bytes_relative(skb, 0, &ip_header, sizeof(ip_header), BPF_HDR_START_NET) < 0) {
            return 0;
        }
        l4_offset = sizeof(ip_header);

        __u32 ver_tc_fl = bpf_ntohl(ip_header.ver_tc_fl);
        pkt.bytes = bpf_ntohs(ip_header.payload_length) + sizeof(ip_header);
        pkt.tos = (ver_tc_fl >> 20) & 0xff;
        pkt.ipttl = ip_header.hop_limit;
        pkt.ipv6_flowlabel = ver_tc_fl & 0x000fffff;
        pkt.src_hi = bpf_be64_to_cpu(ip_header.src_hi);
        pkt.src_lo = bpf_be64_to_cpu(ip_header.src_lo);
        pkt.dst_hi = bpf_be64_to_cpu(ip_header.dst_hi);
        pkt.dst_lo = bpf_be64_to_cpu(ip_header.dst_lo);

        // If more than IPV6_MAX_EXT_HEADERS are chained, proto stays an extension
        // header type and L4 is not parsed.
        __u8 next_header = ip_header.next_header;
        #pragma unroll
        for (int i = 0; i < IPV6_MAX_EXT_HEADERS; i++) {
            if (!is_ipv6_ext_header(next_header)) {
                break;
            }
            ip6_ext_header_t ext_header;
            if (bpf_skb_load_bytes_relative(skb, l4_offset, &ext_header, sizeof(ext_header), BPF_HDR_START_NET) < 0) {
                parse_l4 = 0;
                break;
            }
            if (next_header == IPPROTO_FRAGMENT) {
                l4_offset += 8;
                next_header = ext_header.next_header;
                if ((bpf_ntohs(ext_header.frag_off) & 0xfff8) != 0) { // non-first fragment, no L4 header
                    parse_l4 = 0;
                    break;
                }
                continue;
            }
            if (next_header == IPPROTO_AH) {
                l4_offset += (ext_header.hdr_ext_len + 2) * 4;
            } else {
                l4_offset += (ext_header.hdr_ext_len + 1) * 8;
            }
            next_header = ext_header.next_header;
        }
        pkt.proto = next_header;
    } else {
        return 0;
    }

    // L4
    // A truncated packet is still reported, with zeroed L4 fields.
    if (parse_l4) {
        if (pkt.proto == IPPROTO_TCP) {
            tcp_header_t tcp_header;
            if (bpf_skb_load_bytes_relative(skb, l4_offset, &tcp_header, sizeof(tcp_header), BPF_HDR_START_NET) == 0) {
                pkt.srcport = bpf_ntohs(tcp_header.srcport);
                pkt.dstport = bpf_ntohs(tcp_header.dstport);
                pkt.tcp_flags = tcp_header.flags;
            }
        } else if (pkt.proto == IPPROTO_UDP) {
            udp_header_t udp_header;
            if (bpf_skb_load_bytes_relative(skb, l4_offset, &udp_header, sizeof(udp_header), BPF_HDR_START_NET) == 0) {
                pkt.srcport = bpf_ntohs(udp_header.srcport);
                pkt.dstport = bpf_ntohs(udp_header.dstport);
            }
        } else if (pkt.proto == IPPROTO_ICMP || pkt.proto == IPPROTO_ICMPV6) {
            icmp_header_t icmp_header;
            if (bpf_skb_load_bytes_relative(skb, l4_offset, &icmp_header, sizeof(icmp_header), BPF_HDR_START_NET) == 0) {
                pkt.icmp_type = icmp_header.type;
                pkt.icmp_code = icmp_header.code;
            }
        }
    }

    bpf_perf_event_output(skb, &packets, BPF_F_CURRENT_CPU, &pkt, sizeof(pkt));
    // Data goes out via the perf map only; anything non-zero would also queue the packet on the unread raw socket.
    return 0;
}

char _license[] SEC("license") = "GPL";
