package flowexport

import (
	"net"
	"testing"
	"time"

	"github.com/bwNetFlow/bpf_flowexport/packetdump"
	"github.com/bwNetFlow/flowpipeline/pb"
)

const receiveTimeout = 2 * time.Second

func tcpPacket(srcPort uint16, bytes uint32, flags uint8) packetdump.Packet {
	return packetdump.Packet{
		SrcAddr:  net.ParseIP("10.10.10.1").To4(),
		DstAddr:  net.ParseIP("10.10.10.2").To4(),
		Etype:    0x0800,
		Proto:    6,
		SrcPort:  srcPort,
		DstPort:  443,
		Bytes:    bytes,
		TcpFlags: flags,
	}
}

func newStartedExporter(t *testing.T, activeTimeout, inactiveTimeout string) *FlowExporter {
	t.Helper()
	exporter, err := NewFlowExporter(activeTimeout, inactiveTimeout)
	if err != nil {
		t.Fatal(err)
	}
	exporter.Start(net.ParseIP("10.10.10.10"))
	t.Cleanup(func() {
		exporter.Stop()
		drain(t, exporter)
	})
	return exporter
}

func receive(t *testing.T, exporter *FlowExporter) *pb.EnrichedFlow {
	t.Helper()
	select {
	case flow, ok := <-exporter.Flows:
		if !ok {
			t.Fatal("Flows closed unexpectedly")
		}
		return flow
	case <-time.After(receiveTimeout):
		t.Fatal("no flow exported")
	}
	return nil
}

func assertNothingExported(t *testing.T, exporter *FlowExporter, wait time.Duration) {
	t.Helper()
	select {
	case flow := <-exporter.Flows:
		t.Fatalf("unexpected export: %v", flow)
	case <-time.After(wait):
	}
}

func drain(t *testing.T, exporter *FlowExporter) []*pb.EnrichedFlow {
	t.Helper()
	var flows []*pb.EnrichedFlow
	timeout := time.After(receiveTimeout)
	for {
		select {
		case flow, ok := <-exporter.Flows:
			if !ok {
				return flows
			}
			flows = append(flows, flow)
		case <-timeout:
			t.Fatal("Flows was not closed after Stop")
			return flows
		}
	}
}

func TestInactiveTimeoutAggregates(t *testing.T) {
	exporter := newStartedExporter(t, "1h", "100ms")

	start := time.Now()
	exporter.Insert(tcpPacket(1000, 60, 0x02))
	exporter.Insert(tcpPacket(1000, 1500, 0x10))
	exporter.Insert(tcpPacket(1000, 40, 0x18))

	flow := receive(t, exporter)
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Errorf("exported after %v, before the inactive timeout", elapsed)
	}
	if flow.Packets != 3 || flow.Bytes != 1600 {
		t.Errorf("got %d packets / %d bytes, want 3 / 1600", flow.Packets, flow.Bytes)
	}
	if flow.TCPFlags != 0x1a {
		t.Errorf("got TCP flags %#x, want %#x", flow.TCPFlags, 0x1a)
	}
	if flow.SrcPort != 1000 || flow.DstPort != 443 || flow.Proto != 6 {
		t.Errorf("unexpected key fields: %v", flow)
	}
	if !net.IP(flow.SamplerAddress).Equal(net.ParseIP("10.10.10.10")) {
		t.Errorf("got sampler address %v", net.IP(flow.SamplerAddress))
	}
	if flow.TimeReceived < flow.TimeFlowStart || flow.TimeFlowEnd < flow.TimeFlowStart {
		t.Errorf("inconsistent times: received %d, start %d, end %d", flow.TimeReceived, flow.TimeFlowStart, flow.TimeFlowEnd)
	}
}

func TestActiveTimeout(t *testing.T) {
	exporter := newStartedExporter(t, "200ms", "1h")

	start := time.Now()
	done := make(chan struct{})
	defer close(done)
	go func() {
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				exporter.Insert(tcpPacket(2000, 100, 0x10))
			case <-done:
				return
			}
		}
	}()

	flow := receive(t, exporter)
	elapsed := time.Since(start)
	if elapsed < 200*time.Millisecond || elapsed > time.Second {
		t.Errorf("exported after %v, want shortly after the 200ms active timeout", elapsed)
	}
	if flow.Packets < 2 {
		t.Errorf("got %d packets, want the packets of an ongoing flow", flow.Packets)
	}
}

func TestTcpFinAndRstExportImmediately(t *testing.T) {
	cases := []struct {
		name  string
		flags uint8
	}{
		{"fin", 0x11},
		{"rst", 0x14},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			exporter := newStartedExporter(t, "1h", "1h")

			exporter.Insert(tcpPacket(3000, 100, 0x10))
			assertNothingExported(t, exporter, 50*time.Millisecond)
			exporter.Insert(tcpPacket(3000, 40, testCase.flags))

			flow := receive(t, exporter)
			if flow.Packets != 2 || flow.Bytes != 140 {
				t.Errorf("got %d packets / %d bytes, want 2 / 140", flow.Packets, flow.Bytes)
			}
			if flow.TCPFlags != uint32(testCase.flags) {
				t.Errorf("got TCP flags %#x, want %#x", flow.TCPFlags, testCase.flags)
			}
		})
	}
}

func TestStopFlushesAndClosesFlows(t *testing.T) {
	exporter, err := NewFlowExporter("1h", "1h")
	if err != nil {
		t.Fatal(err)
	}
	exporter.Start(nil)

	for port := uint16(4000); port < 4005; port++ {
		exporter.Insert(tcpPacket(port, 100, 0x10))
	}
	exporter.Stop()
	exporter.Stop()

	flows := drain(t, exporter)
	if len(flows) != 5 {
		t.Fatalf("got %d flows after Stop, want 5", len(flows))
	}

	exporter.Insert(tcpPacket(5000, 100, 0x10))
}

func TestStopUnblocksPendingSend(t *testing.T) {
	exporter, err := NewFlowExporter("1h", "1h")
	if err != nil {
		t.Fatal(err)
	}
	exporter.Start(nil)

	exporter.Insert(tcpPacket(6000, 40, 0x04))
	exporter.Insert(tcpPacket(6001, 40, 0x04))
	exporter.Insert(tcpPacket(6002, 100, 0x10))
	time.Sleep(50 * time.Millisecond)
	exporter.Stop()

	flows := drain(t, exporter)
	if len(flows) != 3 {
		t.Fatalf("got %d flows, want the 2 RST flows plus the 1 cached flow", len(flows))
	}
}

func TestConsumeFromClosedChannel(t *testing.T) {
	exporter, err := NewFlowExporter("1h", "1h")
	if err != nil {
		t.Fatal(err)
	}
	exporter.Start(nil)

	pkts := make(chan packetdump.Packet, 1)
	pkts <- tcpPacket(7000, 100, 0x10)
	close(pkts)
	exporter.ConsumeFrom(pkts)

	exporter.Stop()
	flows := drain(t, exporter)
	if len(flows) != 1 {
		t.Fatalf("got %d flows, want 1 (no zero-value packet from the closed channel)", len(flows))
	}
}

func TestInsertDoesNotBlockOnSlowConsumer(t *testing.T) {
	exporter := newStartedExporter(t, "1h", "1h")

	done := make(chan struct{})
	go func() {
		for port := uint16(8000); port < 8100; port++ {
			exporter.Insert(tcpPacket(port, 40, 0x04))
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(receiveTimeout):
		t.Fatal("Insert blocked while nobody reads Flows")
	}
}

func TestNewFlowExporterRejectsBadTimeouts(t *testing.T) {
	for _, timeouts := range [][2]string{{"0s", "1s"}, {"1s", "-1s"}, {"x", "1s"}, {"1s", "x"}} {
		if _, err := NewFlowExporter(timeouts[0], timeouts[1]); err == nil {
			t.Errorf("NewFlowExporter(%q, %q) succeeded", timeouts[0], timeouts[1])
		}
	}
}
