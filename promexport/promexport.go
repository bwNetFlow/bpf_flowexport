package promexport

// histogram ttl
// histogram TC
// burstiness und micropeaks
// tls bits im payload?
// evil bit

import (
	"fmt"
	"log"
	"net/http"

	"github.com/bwNetFlow/bpf_flowexport/packetdump"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func protoNumToString(proto uint32) string {
	protomap := map[uint32]string{0: "HOPOPT", 1: "ICMP", 2: "IGMP",
		3: "GGP", 4: "IPIP", 5: "ST", 6: "TCP", 7: "CBT", 8: "EGP",
		9: "IGP", 10: "BBN-RCC-MON", 11: "NVP-II", 12: "PUP",
		13: "ARGUS", 14: "EMCON", 15: "XNET", 16: "CHAOS", 17: "UDP",
		18: "MUX", 19: "DCN-MEAS", 20: "HMP", 21: "PRM", 22: "XNS-IDP",
		23: "TRUNK-1", 24: "TRUNK-2", 25: "LEAF-1", 26: "LEAF-2",
		27: "RDP", 28: "IRTP", 29: "ISO-TP4", 30: "NETBLT",
		31: "MFE-NSP", 32: "MERIT-INP", 33: "DCCP", 34: "3PC",
		35: "IDPR", 36: "XTP", 37: "DDP", 38: "IDPR-CMTP", 39: "TP++",
		40: "IL", 41: "IPv6", 42: "SDRP", 43: "IPv6-Route",
		44: "IPv6-Frag", 45: "IDRP", 46: "RSVP", 47: "GRE", 48: "DSR",
		49: "BNA", 50: "ESP", 51: "AH", 52: "I-NLSP", 53: "SwIPe",
		54: "NARP", 55: "MOBILE", 56: "TLSP", 57: "SKIP",
		58: "IPv6-ICMP", 59: "IPv6-NoNxt", 60: "IPv6-Opts",
		61: "Any host internal protocol", 62: "CFTP",
		63: "Any local network", 64: "SAT-EXPAK", 65: "KRYPTOLAN",
		66: "RVD", 67: "IPPC", 68: "Any distributed file system",
		69: "SAT-MON", 70: "VISA", 71: "IPCU", 72: "CPNX", 73: "CPHB",
		74: "WSN", 75: "PVP", 76: "BR-SAT-MON", 77: "SUN-ND",
		78: "WB-MON", 79: "WB-EXPAK", 80: "ISO-IP", 81: "VMTP",
		82: "SECURE-VMTP", 83: "VINES", 84: "TTP", 85: "NSFNET-IGP",
		86: "DGP", 87: "TCF", 88: "EIGRP", 89: "OSPF",
		90: "Sprite-RPC", 91: "LARP", 92: "MTP", 93: "AX.25", 94: "OS",
		95: "MICP", 96: "SCC-SP", 97: "ETHERIP", 98: "ENCAP",
		99: "Any private encryption scheme", 100: "GMTP", 101: "IFMP",
		102: "PNNI", 103: "PIM", 104: "ARIS", 105: "SCPS", 106: "QNX",
		107: "A/N", 108: "IPComp", 109: "SNP", 110: "Compaq-Peer",
		111: "IPX-in-IP", 112: "VRRP", 113: "PGM",
		114: "Any 0-hop protocol", 115: "L2TP", 116: "DDX",
		117: "IATP", 118: "STP", 119: "SRP", 120: "UTI", 121: "SMP",
		122: "SM", 123: "PTP", 124: "IS-IS over IPv4", 125: "FIRE",
		126: "CRTP", 127: "CRUDP", 128: "SSCOPMCE", 129: "IPLT",
		130: "SPS", 131: "PIPE", 132: "SCTP", 133: "FC",
		134: "RSVP-E2E-IGNORE", 135: "Mobility Header", 136: "UDPLite",
		137: "MPLS-in-IP", 138: "manet", 139: "HIP", 140: "Shim6",
		141: "WESP", 142: "ROHC", 143: "Ethernet",
	}
	return protomap[proto]
}

func etypeNumToString(etype uint32) string {
	etypemap := map[uint32]string{0x86dd: "IPv6", 0x0800: "IPv4"}
	if _, ok := etypemap[etype]; !ok {
		return fmt.Sprintf("%04x", etype)
	}
	return etypemap[etype]
}

type PacketStatExporter struct {
	stop    chan bool
	packets *prometheus.CounterVec
	bytes   *prometheus.CounterVec
}

func (e *PacketStatExporter) ConsumeFrom(pkts chan packetdump.Packet) {
	e.stop = make(chan bool)
	go func() {
		for {
			select {
			case pkt, ok := <-pkts:
				e.packets.WithLabelValues(etypeNumToString(pkt.Etype), protoNumToString(pkt.Proto)).Inc()
				e.bytes.WithLabelValues(etypeNumToString(pkt.Etype), protoNumToString(pkt.Proto)).Add(float64(pkt.Bytes))
				if !ok {
					return
				}
			case <-e.stop:
				return
			}
		}
	}()
}

func (e *PacketStatExporter) Start() {
	e.packets = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "packet_total",
		Help: "The total number of packets",
	}, []string{"etype", "proto"})
	e.bytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "packet_bytes",
		Help: "The number of bytes in all packets",
	}, []string{"etype", "proto"})
	log.Println("[info] PacketStatExporter: Starting Prometheus export on port 9999.")
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(":9999", nil)
}

func (e *PacketStatExporter) Stop() {
	log.Println("[info] PacketStatExporter: Stopping packet consumption goroutines.")
	close(e.stop)
}
