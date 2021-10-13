package main

import (
	"fmt"
	"os"

	"github.com/bwNetFlow/bpfdump"
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

	dumper := &bpfdump.BpfPacketDumper{}

	err := dumper.Setup(device)
	if err != nil {
		fmt.Println(err)
	}
	err = dumper.Start()
	if err != nil {
		fmt.Println(err)
	}
	defer dumper.Stop()

	fmt.Println("Capturing packets, hit CTRL+C to stop")
	for packet := range dumper.Packets() {
		var protoextra string
		if packet.Etype == 0x0800 {
			if packet.Proto == 1 {
				protoextra = fmt.Sprintf(" (%d|%d)", packet.IcmpType, packet.IcmpCode)
			} else if packet.Proto == 6 {
				protoextra = fmt.Sprintf(" (s:%d|a:%d|f:%d)", (packet.TcpFlags&0b10)>>1, (packet.TcpFlags&0b10000)>>4, packet.TcpFlags&0b1)
			}
		} else {
			if packet.Proto == 58 {
				protoextra = fmt.Sprintf(" (%d|%d)", packet.IcmpType, packet.IcmpCode)
			} else if packet.Proto == 6 {
				protoextra = fmt.Sprintf(" (s:%d|a:%d|f:%d)", (packet.TcpFlags&0b10)>>1, (packet.TcpFlags&0b10000)>>4, packet.TcpFlags&0b1)
			}
		}
		var dir string
		if packet.IngressIface == packet.CollectIface {
			dir = " in"
		} else {
			dir = "out"
		}
		fmt.Printf("%s: bytes %d, etype %x, proto %d%s, ttl %d, tos %b, %s:%d -> %s:%d\n", dir, packet.Bytes, packet.Etype, packet.Proto, protoextra, packet.IPTtl, packet.IPTos, packet.SrcAddr, packet.SrcPort, packet.DstAddr, packet.DstPort)
	}
}
