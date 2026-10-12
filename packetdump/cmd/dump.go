package main

import (
	"fmt"
	"os"

	"github.com/bwNetFlow/bpf_flowexport/packetdump"
)

func usage() {
	fmt.Printf("Usage: %v <ifdev>\n", os.Args[0])
	fmt.Printf("e.g.: %v eth0\n", os.Args[0])
	os.Exit(1)
}

func main() {
	if len(os.Args) != 2 {
		usage()
	}
	device := os.Args[1]

	dumper := &packetdump.PacketDumper{}

	if err := dumper.Setup(device); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if err := dumper.Start(); err != nil {
		fmt.Println(err)
		dumper.Stop()
		os.Exit(1)
	}
	defer dumper.Stop()

	fmt.Println("Capturing packets, hit CTRL+C to stop")
	for packet := range dumper.Packets() {
		var protoextra string
		if packet.Etype == 0x0800 {
			if packet.Proto == 1 {
				protoextra = fmt.Sprintf(" (%d|%d)", packet.IcmpType, packet.IcmpCode)
			} else if packet.Proto == 6 {
				protoextra = fmt.Sprintf(" (s:%d|a:%d|r:%d|f:%d)", (packet.TcpFlags&0b10)>>1, (packet.TcpFlags&0b10000)>>4, (packet.TcpFlags&0b100)>>2, packet.TcpFlags&0b1)
			}
		} else {
			if packet.Proto == 58 {
				protoextra = fmt.Sprintf(" (%d|%d)", packet.IcmpType, packet.IcmpCode)
			} else if packet.Proto == 6 {
				protoextra = fmt.Sprintf(" (s:%d|a:%d|r:%d|f:%d)", (packet.TcpFlags&0b10)>>1, (packet.TcpFlags&0b10000)>>4, (packet.TcpFlags&0b100)>>2, packet.TcpFlags&0b1)
			}
		}
		dir := " in"
		if packet.FlowDirection == 1 {
			dir = "out"
		}
		fmt.Printf("%s: bytes %d, etype %x, proto %d%s, ttl %d, tos %b, %s:%d -> %s:%d\n", dir, packet.Bytes, packet.Etype, packet.Proto, protoextra, packet.IPTtl, packet.IPTos, packet.SrcAddr, packet.SrcPort, packet.DstAddr, packet.DstPort)
	}
}
