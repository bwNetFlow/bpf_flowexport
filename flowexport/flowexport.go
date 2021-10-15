package flowexport

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/bwNetFlow/bpf_flowexport/bpf"
	flow "github.com/bwNetFlow/protobuf/go"
)

type FlowKey struct {
	SrcAddr string
	DstAddr string
	SrcPort uint16
	DstPort uint16
	Proto   uint32
	IPTos   uint8
	InIface uint32
}

func NewFlowKey(pkt bpf.Packet) FlowKey {
	return FlowKey{
		SrcAddr: string(pkt.SrcAddr.To16()),
		DstAddr: string(pkt.DstAddr.To16()),
		SrcPort: pkt.SrcPort,
		DstPort: pkt.DstPort,
		Proto:   pkt.Proto,
		IPTos:   pkt.IPTos,
		InIface: pkt.IngressIface,
	}
}

type FlowRecord struct {
	TimeReceived time.Time
	LastUpdated  time.Time
	Packets      []bpf.Packet
}

func BuildFlow(f *FlowRecord) *flow.FlowMessage {
	flow := &flow.FlowMessage{}
	flow.TimeReceived = uint64(f.TimeReceived.Unix())
	flow.TimeFlowStart = uint64(f.TimeReceived.Unix())
	flow.TimeFlowEnd = uint64(f.LastUpdated.Unix())
	for i, pkt := range f.Packets {
		if i == 0 {
			// flow key 7-tuple
			flow.SrcAddr = pkt.SrcAddr
			flow.DstAddr = pkt.DstAddr
			flow.SrcPort = uint32(pkt.SrcPort)
			flow.DstPort = uint32(pkt.DstPort)
			flow.Proto = pkt.Proto
			flow.IPTos = uint32(pkt.IPTos)
			flow.InIf = pkt.IngressIface

			// other presumably static data
			flow.Etype = pkt.Etype
			flow.IPv6FlowLabel = pkt.Ipv6FlowLabel
			flow.IPTTL = uint32(pkt.IPTtl)
			flow.IcmpType = uint32(pkt.IcmpType)
			flow.IcmpCode = uint32(pkt.IcmpCode)

			// additional assumptions TODO: aaaaargh
			// TODO: whats up with bridge ifaces
			flow.OutIf = pkt.CollectIface // TODO: think about this...
			if pkt.IngressIface == 0 {
				// if ingress iface is 0, the flow is locally originated
				flow.FlowDirection = 0 // egress flow marker
				flow.RemoteAddr = 2    // dst addr is remote
			} else if pkt.IngressIface == pkt.CollectIface {
				// if ingress iface is the same that we collected on, the flow is ingress into this host
				flow.OutIf = 0         // in that case, OutIf != InIf... TODO: what about loops?
				flow.FlowDirection = 1 // ingress flow marker
				flow.RemoteAddr = 1    // src addr is remote
			} else if pkt.IngressIface != pkt.CollectIface {
				// if ingress iface and collect iface differ, the flow is being forwarded through the collect iface
				flow.FlowDirection = 0 // egress flow marker
				flow.RemoteAddr = 0    // both are remote
			}
		}

		// plausibility checks TODO: remove/make less laughable, also check on OutIf...
		if flow.IPv6FlowLabel != pkt.Ipv6FlowLabel {
			fmt.Println("wat Ipv6FlowLabel")
		}
		if flow.IPTTL != uint32(pkt.IPTtl) {
			fmt.Println("wat IPTTL")
		}
		if flow.IcmpType != uint32(pkt.IcmpType) {
			fmt.Println("wat IcmpType")
		}
		if flow.IcmpCode != uint32(pkt.IcmpCode) {
			fmt.Println("wat IcmpCode")
		}

		// special handling
		flow.TCPFlags = flow.TCPFlags | uint32(pkt.TcpFlags)
		flow.Bytes += uint64(pkt.Bytes)
		flow.Packets += 1
	}
	return flow
}

type FlowExporter struct {
	activeTimeout   time.Duration
	inactiveTimeout time.Duration

	Flows chan *flow.FlowMessage

	mutex *sync.RWMutex
	stop  chan bool
	cache map[FlowKey]*FlowRecord
}

func NewFlowExporter(activeTimeout string, inactiveTimeout string) (*FlowExporter, error) {
	activeTimeoutDuration, err := time.ParseDuration(activeTimeout)
	if err != nil {
		return nil, fmt.Errorf("active timeout misconfigured")
	}
	inactiveTimeoutDuration, err := time.ParseDuration(inactiveTimeout)
	if err != nil {
		return nil, fmt.Errorf("inactive timeout misconfigured")
	}

	fe := &FlowExporter{activeTimeout: activeTimeoutDuration, inactiveTimeout: inactiveTimeoutDuration}
	fe.Flows = make(chan *flow.FlowMessage)

	fe.mutex = &sync.RWMutex{}
	fe.cache = make(map[FlowKey]*FlowRecord)

	return fe, nil
}

func (f *FlowExporter) Start() {
	log.Println("[info] FlowExporter: Starting export goroutines.")
	f.stop = make(chan bool)
	go f.exportInactive()
	go f.exportActive()
}

func (f *FlowExporter) Stop() {
	log.Println("[info] FlowExporter: Stopping export goroutines.")
	close(f.stop)
}

func (f *FlowExporter) exportInactive() {
	ticker := time.NewTicker(f.inactiveTimeout)
	for {
		select {
		case <-ticker.C:
			now := time.Now()

			f.mutex.Lock()
			for key, record := range f.cache {
				if now.Sub(record.LastUpdated) > f.inactiveTimeout {
					f.export(key)
				}
			}
			f.mutex.Unlock()
		case <-f.stop:
			ticker.Stop()
			return
		}
	}
}

func (f *FlowExporter) exportActive() {
	ticker := time.NewTicker(f.activeTimeout)
	for {
		select {
		case <-ticker.C:
			now := time.Now()

			f.mutex.Lock()
			for key, record := range f.cache {
				if now.Sub(record.TimeReceived) > f.activeTimeout {
					f.export(key)
				}
			}
			f.mutex.Unlock()
		case <-f.stop:
			ticker.Stop()
			return
		}
	}
}

func (f *FlowExporter) Insert(pkt bpf.Packet) {
	key := NewFlowKey(pkt)

	var record *FlowRecord
	var exists bool

	f.mutex.Lock()
	if record, exists = f.cache[key]; !exists {
		f.cache[key] = new(FlowRecord)
		f.cache[key].TimeReceived = time.Now()
		record = f.cache[key]
	}
	record.LastUpdated = time.Now()
	record.Packets = append(record.Packets, pkt)
	if pkt.TcpFlags&0b1 == 1 { // short cut flow export if we see TCP FIN
		f.export(key)
	}
	f.mutex.Unlock()
}

func (f *FlowExporter) ConsumeFrom(pkts chan bpf.Packet) {
	for {
		select {
		case pkt, ok := <-pkts:
			f.Insert(pkt)
			if !ok {
				return
			}
		case <-f.stop:
			return
		}
	}
}

func (f *FlowExporter) export(key FlowKey) {
	flowRecord := f.cache[key]
	delete(f.cache, key)

	f.Flows <- BuildFlow(flowRecord)
}
