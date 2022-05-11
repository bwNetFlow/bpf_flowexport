package flowexport

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/bwNetFlow/bpf_flowexport/packetdump"
	"github.com/bwNetFlow/flowpipeline/pb"
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

func NewFlowKey(pkt packetdump.Packet) FlowKey {
	return FlowKey{
		SrcAddr: string(pkt.SrcAddr.To16()),
		DstAddr: string(pkt.DstAddr.To16()),
		SrcPort: pkt.SrcPort,
		DstPort: pkt.DstPort,
		Proto:   pkt.Proto,
		IPTos:   pkt.IPTos,
		InIface: pkt.InIf,
	}
}

type FlowRecord struct {
	TimeReceived time.Time
	LastUpdated  time.Time
	Packets      []packetdump.Packet
}

func BuildFlow(f *FlowRecord) *pb.EnrichedFlow {
	msg := &pb.EnrichedFlow{}
	msg.TimeReceived = uint64(f.TimeReceived.Unix())
	msg.TimeFlowStart = uint64(f.TimeReceived.Unix())
	msg.TimeFlowEnd = uint64(f.LastUpdated.Unix())
	for i, pkt := range f.Packets {
		if i == 0 {
			// flow key 7-tuple
			msg.SrcAddr = pkt.SrcAddr
			msg.DstAddr = pkt.DstAddr
			msg.SrcPort = uint32(pkt.SrcPort)
			msg.DstPort = uint32(pkt.DstPort)
			msg.Proto = pkt.Proto
			msg.IPTos = uint32(pkt.IPTos)
			msg.InIf = pkt.InIf

			// other presumably static data, this will be set to the first packets fields
			msg.OutIf = pkt.OutIf
			msg.FlowDirection = uint32(pkt.FlowDirection)                   // this is derived from the packets type
			msg.RemoteAddr = pb.EnrichedFlow_RemoteAddrType(pkt.RemoteAddr) // this is derived from the packets type
			msg.Etype = pkt.Etype
			msg.IPv6FlowLabel = pkt.Ipv6FlowLabel // TODO: no differences possible?
			msg.IPTTL = uint32(pkt.IPTtl)         // TODO: set to lowest if differ?
			msg.IcmpType = uint32(pkt.IcmpType)   // TODO: differences could occur between packets
			msg.IcmpCode = uint32(pkt.IcmpCode)   // TODO: differences could occur between packets
		}
		// special handling
		msg.TCPFlags = msg.TCPFlags | uint32(pkt.TcpFlags)
		msg.Bytes += uint64(pkt.Bytes)
		msg.Packets += 1
	}
	return msg
}

type FlowExporter struct {
	activeTimeout   time.Duration
	inactiveTimeout time.Duration

	Flows chan *pb.EnrichedFlow

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
	fe.Flows = make(chan *pb.EnrichedFlow)

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

func (f *FlowExporter) Insert(pkt packetdump.Packet) {
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

func (f *FlowExporter) ConsumeFrom(pkts chan packetdump.Packet) {
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
