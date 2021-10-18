#include <linux/types.h> // __u* types

#include <arpa/inet.h> // *_t types
#include <linux/bpf.h> // BPF constants
#include <bpf/bpf_helpers.h> // SEC macro
// or from headers dir: #include "bpf_helpers.h"

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
  uint8_t  dstaddr[6];
  uint8_t  srcaddr[6];
  uint16_t llc_len;
} ether_header_t;

typedef struct {
  uint8_t  ver_ihl;
  uint8_t  tos;
  uint16_t total_length;
  uint16_t id;
  uint16_t flags_fo;
  uint8_t  ttl;
  uint8_t  protocol;
  uint16_t checksum;
  uint32_t srcaddr;
  uint32_t dstaddr;
} ip4_header_t;

typedef struct {
  uint32_t ver_tc_fl;
  uint16_t payload_length;
  uint8_t next_header;
  uint8_t hop_limit;
  unsigned long long src_hi;
  unsigned long long src_lo;
  unsigned long long dst_hi;
  unsigned long long dst_lo;
} ip6_header_t;

typedef struct {
  uint16_t srcport;
  uint16_t dstport;
  uint32_t seq;
  uint32_t ack;
  uint8_t  data_offset; // and 4 extra bits
  uint8_t  flags;
  // remainder does not matter
} tcp_header_t;

typedef struct {
  uint16_t srcport;
  uint16_t dstport;
  // remainder does not matter
} udp_header_t;

typedef struct {
  uint8_t type;
  uint8_t code;
} icmp_header_t;
#pragma pack(pop)

typedef struct {
    unsigned long long  src_hi; // L3
    unsigned long long  src_lo; // L3
    unsigned long long  dst_hi; // L3
    unsigned long long  dst_lo; // L3
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
    __u8 icmp_type; // L4 TODO
    __u8 icmp_code; // L4 TODO
    __u8 tcp_flags; // L4
} packet_t;

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} packets SEC(".maps");

SEC("socket1")
int packet_dump(struct __sk_buff *skb) {

    packet_t pkt = {};

    // L1
    // TODO: fix below if
    if (skb->pkt_type == PACKET_HOST) { // to us
        // pkt.direction = 0
        // pkt.remoteaddr = src
        pkt.inif = skb->ingress_ifindex; // should be equal to ifindex
        pkt.outif = 0;
    } else if (skb->pkt_type == PACKET_OUTGOING) { // from us
        // pkt.direction = 1
        // pkt.remoteaddr = dst
        pkt.inif = skb->ingress_ifindex;
        pkt.outif = skb->ifindex;
    }

    // L2
    pkt.etype = htons(skb->protocol);

    // L3
    short IHL = 40; // v6 header len, v4 will overwrite
    if (pkt.etype == ETH_P_IP) {
        ip4_header_t ip_header;
        bpf_skb_load_bytes(skb, ETH_HLEN, &ip_header, 20);

        IHL = 4 * (ip_header.ver_ihl & 0x0f);

        pkt.bytes = ntohs(ip_header.total_length);
        pkt.proto = ip_header.protocol;
        pkt.tos = ip_header.tos;
        pkt.ipttl = ip_header.ttl;
        pkt.srcaddr = ntohl(ip_header.srcaddr);
        pkt.dstaddr = ntohl(ip_header.dstaddr);
    } else if (pkt.etype == ETH_P_IPV6) {
        ip6_header_t ip_header;
        bpf_skb_load_bytes(skb, ETH_HLEN, &ip_header, 40);

        pkt.bytes = ntohs(ip_header.payload_length);
        pkt.proto = ip_header.next_header;
        pkt.tos = (ntohs(ip_header.ver_tc_fl) & 0x0ff00000)>>20;
        pkt.ipttl = ip_header.hop_limit;
        pkt.ipv6_flowlabel = ntohs(ip_header.ver_tc_fl) & 0x000fffff;
        pkt.src_hi = be64toh(ip_header.src_hi);
        pkt.src_lo = be64toh(ip_header.src_lo);
        pkt.dst_hi = be64toh(ip_header.dst_hi);
        pkt.dst_lo = be64toh(ip_header.dst_lo);
    } else {
        return -1;
    }

    // L4
    if (pkt.proto == IPPROTO_TCP) {
        tcp_header_t tcp_header;
        bpf_skb_load_bytes(skb, ETH_HLEN + IHL, &tcp_header, 14);

        pkt.srcport = ntohs(tcp_header.srcport);
        pkt.dstport = ntohs(tcp_header.dstport);
        pkt.tcp_flags = tcp_header.flags;
    } else if (pkt.proto == IPPROTO_UDP) {
        udp_header_t udp_header;
        bpf_skb_load_bytes(skb, ETH_HLEN + IHL, &udp_header, 4);

        pkt.srcport = ntohs(udp_header.srcport);
        pkt.dstport = ntohs(udp_header.dstport);
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

