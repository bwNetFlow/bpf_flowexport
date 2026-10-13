package flowexport

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/bwNetFlow/bpf_flowexport/packetdump"
	"github.com/bwNetFlow/flowpipeline/pb"
)

const (
	tcpFlagFin = 0x01
	tcpFlagRst = 0x04

	minTickInterval = time.Millisecond
	maxTickInterval = time.Second

	defaultFlushTimeout = 5 * time.Second
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
	// Deprecated: never set, use TimeFlowStart.
	TimeReceived time.Time
	// Deprecated: never set, use TimeFlowEnd.
	LastUpdated time.Time

	SamplerAddress net.IP
	TimeFlowStart  time.Time
	TimeFlowEnd    time.Time
	FirstPacket    packetdump.Packet // source of the key and the presumably static non-key fields
	Bytes          uint64
	PacketCount    uint64
	TcpFlags       uint8

	// Deprecated: never set, packets are no longer kept. Use FirstPacket, Bytes, PacketCount and TcpFlags.
	Packets []packetdump.Packet
}

func (record *FlowRecord) add(pkt packetdump.Packet, now time.Time) {
	record.TimeFlowEnd = now
	record.Bytes += uint64(pkt.Bytes)
	record.PacketCount += 1
	record.TcpFlags |= pkt.TcpFlags
}

func BuildFlow(record *FlowRecord) *pb.EnrichedFlow {
	pkt := record.FirstPacket
	msg := &pb.EnrichedFlow{}
	msg.Type = pb.EnrichedFlow_EBPF
	msg.SamplerAddress = record.SamplerAddress
	msg.TimeReceived = uint64(record.TimeFlowStart.Unix())
	msg.TimeFlowStart = uint64(record.TimeFlowStart.Unix())
	msg.TimeFlowEnd = uint64(record.TimeFlowEnd.Unix())

	// flow key 7-tuple
	msg.SrcAddr = pkt.SrcAddr
	msg.DstAddr = pkt.DstAddr
	msg.SrcPort = uint32(pkt.SrcPort)
	msg.DstPort = uint32(pkt.DstPort)
	msg.Proto = pkt.Proto
	msg.IPTos = uint32(pkt.IPTos)
	msg.InIf = pkt.InIf

	msg.OutIf = pkt.OutIf
	msg.FlowDirection = uint32(pkt.FlowDirection)
	msg.RemoteAddr = pb.EnrichedFlow_RemoteAddrType(pkt.RemoteAddr)
	msg.Etype = pkt.Etype
	msg.IPv6FlowLabel = pkt.Ipv6FlowLabel // TODO: no differences possible?
	msg.IPTTL = uint32(pkt.IPTtl)         // TODO: set to lowest if differ?
	msg.IcmpType = uint32(pkt.IcmpType)   // TODO: differences could occur between packets
	msg.IcmpCode = uint32(pkt.IcmpCode)   // TODO: differences could occur between packets

	msg.TCPFlags = uint32(record.TcpFlags)
	msg.Bytes = record.Bytes
	msg.Packets = record.PacketCount
	return msg
}

type FlowExporter struct {
	activeTimeout   time.Duration
	inactiveTimeout time.Duration

	// Flows receives every exported flow. After Stop it receives the remaining
	// cached flows and is then closed, so consumers should read until it is closed.
	Flows chan *pb.EnrichedFlow

	// If Flows goes unread for flushTimeout during that flush, the rest is dropped.
	flushTimeout time.Duration

	stop     chan struct{}
	stopOnce sync.Once
	wake     chan struct{}

	mutex          sync.Mutex
	samplerAddress net.IP
	cache          map[FlowKey]*FlowRecord
	expired        []*FlowRecord
	stopped        bool
}

func NewFlowExporter(activeTimeout string, inactiveTimeout string) (*FlowExporter, error) {
	activeTimeoutDuration, err := time.ParseDuration(activeTimeout)
	if err != nil || activeTimeoutDuration <= 0 {
		return nil, fmt.Errorf("active timeout misconfigured")
	}
	inactiveTimeoutDuration, err := time.ParseDuration(inactiveTimeout)
	if err != nil || inactiveTimeoutDuration <= 0 {
		return nil, fmt.Errorf("inactive timeout misconfigured")
	}

	return &FlowExporter{
		activeTimeout:   activeTimeoutDuration,
		inactiveTimeout: inactiveTimeoutDuration,
		flushTimeout:    defaultFlushTimeout,
		Flows:           make(chan *pb.EnrichedFlow),
		stop:            make(chan struct{}),
		wake:            make(chan struct{}, 1),
		cache:           make(map[FlowKey]*FlowRecord),
	}, nil
}

func (exporter *FlowExporter) Start(samplerAddress net.IP) {
	log.Println("[info] FlowExporter: Starting export goroutine.")

	exporter.mutex.Lock()
	exporter.samplerAddress = samplerAddress
	exporter.mutex.Unlock()
	go exporter.run()
}

func (exporter *FlowExporter) Stop() {
	log.Println("[info] FlowExporter: Stopping export goroutine.")
	exporter.stopOnce.Do(func() { close(exporter.stop) })
}

func (exporter *FlowExporter) Insert(pkt packetdump.Packet) {
	key := NewFlowKey(pkt)
	now := time.Now()

	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()
	if exporter.stopped {
		return
	}

	record, exists := exporter.cache[key]
	if !exists {
		record = &FlowRecord{
			SamplerAddress: exporter.samplerAddress,
			TimeFlowStart:  now,
			FirstPacket:    pkt,
		}
		exporter.cache[key] = record
	}
	record.add(pkt, now)

	if pkt.TcpFlags&(tcpFlagFin|tcpFlagRst) != 0 {
		delete(exporter.cache, key)
		exporter.expired = append(exporter.expired, record)
		select {
		case exporter.wake <- struct{}{}:
		default:
		}
	}
}

func (exporter *FlowExporter) ConsumeFrom(pkts chan packetdump.Packet) {
	for {
		select {
		case pkt, ok := <-pkts:
			if !ok {
				return
			}
			exporter.Insert(pkt)
		case <-exporter.stop:
			return
		}
	}
}

// run owns all sends on Flows, so Insert never blocks on a slow consumer.
func (exporter *FlowExporter) run() {
	defer close(exporter.Flows)

	ticker := time.NewTicker(max(min(exporter.activeTimeout/4, exporter.inactiveTimeout/4, maxTickInterval), minTickInterval))
	defer ticker.Stop()

	for {
		select {
		case now := <-ticker.C:
			exporter.expire(now)
		case <-exporter.wake:
		case <-exporter.stop:
			exporter.flush(nil)
			return
		}
		if unsent := exporter.send(exporter.takeExpired()); unsent != nil {
			exporter.flush(unsent)
			return
		}
	}
}

func (exporter *FlowExporter) expire(now time.Time) {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()
	for key, record := range exporter.cache {
		if now.Sub(record.TimeFlowEnd) > exporter.inactiveTimeout || now.Sub(record.TimeFlowStart) > exporter.activeTimeout {
			delete(exporter.cache, key)
			exporter.expired = append(exporter.expired, record)
		}
	}
}

func (exporter *FlowExporter) takeExpired() []*FlowRecord {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()
	records := exporter.expired
	exporter.expired = nil
	return records
}

// send returns the records it could not deliver before Stop.
func (exporter *FlowExporter) send(records []*FlowRecord) []*FlowRecord {
	for i, record := range records {
		select {
		case exporter.Flows <- BuildFlow(record):
		case <-exporter.stop:
			return records[i:]
		}
	}
	return nil
}

func (exporter *FlowExporter) flush(unsent []*FlowRecord) {
	exporter.mutex.Lock()
	exporter.stopped = true
	records := append(unsent, exporter.expired...)
	for _, record := range exporter.cache {
		records = append(records, record)
	}
	exporter.expired = nil
	clear(exporter.cache)
	exporter.mutex.Unlock()

	// Restart timer every time, so a slow consumer still gets all flows
	idle := time.NewTimer(exporter.flushTimeout)
	defer idle.Stop()
	for i, record := range records {
		select {
		case exporter.Flows <- BuildFlow(record):
			idle.Reset(exporter.flushTimeout)
		case <-idle.C:
			log.Printf("[warning] FlowExporter: Dropped %d flows on Stop, Flows was not read for %v.", len(records)-i, exporter.flushTimeout)
			return
		}
	}
}
