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


#define ICMP 	1
#define TCP 	6
#define UDP 	17
#define ICMPv6 	58

#pragma pack(push, 1)
typedef struct {
  __u8  dstaddr[6];
  __u8  srcaddr[6];
  __u16 llc_len;
} ether_header_t;

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
    __u32 bytes; // len(L2 payload)
    __u32 etype; // L2
    __u32 proto; // L3
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

SEC("socket")
int packet_dump(struct __sk_buff *skb) {

    packet_t pkt = {};

    // L1
    //
    pkt.inif = skb->ingress_ifindex;
    if (skb->pkt_type == PACKET_HOST) { // to us
        pkt.direction = 0; // ingress
        pkt.remoteaddr = 1; // remote address is srcaddr
        pkt.outif = 0; // we don't have any info without our fib
    } else if (skb->pkt_type == PACKET_OUTGOING) { // from us
        pkt.direction = 1; // egress
        pkt.remoteaddr = 2; // remote address is dstaddr
        pkt.outif = skb->ifindex; // since it's egress, we're the outif
    }

    // L2
    pkt.etype = bpf_ntohs(skb->protocol);

    // L3
    short IHL = 40; // v6 header len, v4 will overwrite
    if (pkt.etype == ETH_P_IP) {
        ip4_header_t ip_header;
        bpf_skb_load_bytes(skb, ETH_HLEN, &ip_header, 20);

        IHL = 4 * (ip_header.ver_ihl & 0x0f);

        pkt.bytes = bpf_ntohs(ip_header.total_length);
        pkt.proto = ip_header.protocol;
        pkt.tos = ip_header.tos;
        pkt.ipttl = ip_header.ttl;
        pkt.srcaddr = bpf_ntohl(ip_header.srcaddr);
        pkt.dstaddr = bpf_ntohl(ip_header.dstaddr);
    } else if (pkt.etype == ETH_P_IPV6) {
        ip6_header_t ip_header;
        bpf_skb_load_bytes(skb, ETH_HLEN, &ip_header, 40);

        pkt.bytes = bpf_ntohs(ip_header.payload_length);
        pkt.proto = ip_header.next_header;
        pkt.tos = (bpf_ntohs(ip_header.ver_tc_fl) & 0x0ff00000)>>20;
        pkt.ipttl = ip_header.hop_limit;
        pkt.ipv6_flowlabel = bpf_ntohs(ip_header.ver_tc_fl) & 0x000fffff;
        pkt.src_hi = bpf_be64_to_cpu(ip_header.src_hi);
        pkt.src_lo = bpf_be64_to_cpu(ip_header.src_lo);
        pkt.dst_hi = bpf_be64_to_cpu(ip_header.dst_hi);
        pkt.dst_lo = bpf_be64_to_cpu(ip_header.dst_lo);
    } else {
        return -1;
    }

    // L4
    if (pkt.proto == IPPROTO_TCP) {
        tcp_header_t tcp_header;
        bpf_skb_load_bytes(skb, ETH_HLEN + IHL, &tcp_header, 14);

        pkt.srcport = bpf_ntohs(tcp_header.srcport);
        pkt.dstport = bpf_ntohs(tcp_header.dstport);
        pkt.tcp_flags = tcp_header.flags;
    } else if (pkt.proto == IPPROTO_UDP) {
        udp_header_t udp_header;
        bpf_skb_load_bytes(skb, ETH_HLEN + IHL, &udp_header, 4);

        pkt.srcport = bpf_ntohs(udp_header.srcport);
        pkt.dstport = bpf_ntohs(udp_header.dstport);
    } else if (pkt.proto == IPPROTO_ICMP || pkt.proto == IPPROTO_ICMPV6) {
        icmp_header_t icmp_header;
        bpf_skb_load_bytes(skb, ETH_HLEN + IHL, &icmp_header, 2);

        pkt.icmp_type = icmp_header.type;
        pkt.icmp_code = icmp_header.code;
    }

    bpf_perf_event_output(skb, &packets, BPF_F_CURRENT_CPU, &pkt, sizeof(pkt));
    return -1;
}

char _license[] SEC("license") = "GPL";

