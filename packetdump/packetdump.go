//go:build linux
// +build linux

package packetdump

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"

	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-13 -cflags "-O2 -g -Wall -Werror" bpf ./bpf/bpf.c
type rawPacket struct {
	SrcAddrHi     uint64
	SrcAddrLo     uint64
	DstAddrHi     uint64
	DstAddrLo     uint64
	InIf          uint32
	OutIf         uint32
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
	FlowDirection uint8
	RemoteAddr    uint8
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
		InIf:          rawPacket.InIf,
		OutIf:         rawPacket.OutIf,
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
		FlowDirection: rawPacket.FlowDirection,
		RemoteAddr:    rawPacket.RemoteAddr,
	}
}

type PacketDumper struct {
	packets chan Packet // exported through .Packets()

	// setup
	objs           bpfObjects
	socketFilterFd int
	iface          *net.Interface

	// start
	socketFd   int
	perfReader *perf.Reader
}

func (b *PacketDumper) Packets() chan Packet {
	if b.packets != nil {
		return b.packets
	}
	b.packets = make(chan Packet)
	go func() {
		var rawPacket rawPacket
		for {
			record, err := b.perfReader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				log.Printf("[error] BPF packet dump: Error reading from kernel perf event reader: %s", err)
				continue
			}

			if record.LostSamples != 0 {
				log.Printf("[warning] BPF packet dump: Kernel perf event buffer full, dropped %d samples", record.LostSamples)
				continue
			}

			// Parse the perf event entry into an Event structure.
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &rawPacket); err != nil {
				log.Printf("[error] BPF packet dump: Skipped 1 sample, error decoding raw perf event data: %s", err)
				continue
			}
			b.packets <- parseRawPacket(rawPacket)
		}
	}()
	return b.packets
}

func (b *PacketDumper) Setup(device string) error {
	// allow the current process to lock memory for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("[error] BPF packet dump: Error during required memlock removal: %s", err)
	}

	b.objs = bpfObjects{} // load pre-compiled programs and maps into the kernel
	if err := loadBpfObjects(&b.objs, nil); err != nil {
		log.Fatalf("[error] BPF packet dump: Error loading objects: %v", err)
	}

	var err error
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

	if err := syscall.SetsockoptInt(b.socketFd, syscall.SOL_SOCKET, 50, b.objs.PacketDump.FD()); err != nil {
		return fmt.Errorf("Unable to attach BPF socket filter: %v", err)
	}

	b.perfReader, err = perf.NewReader(b.objs.Packets, os.Getpagesize())
	if err != nil {
		return fmt.Errorf("Unable to connect kernel perf event reader: %s", err)
	}

	return nil
}

func (b *PacketDumper) Stop() {
	b.objs.Close()
	syscall.Close(b.socketFd)
	b.perfReader.Close()
}
