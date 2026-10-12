package main

import (
	"fmt"
	"os"

	"github.com/bwNetFlow/bpf_flowexport/packetdump"
	"github.com/bwNetFlow/bpf_flowexport/promexport"
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

	export := &promexport.PacketStatExporter{}
	export.ConsumeFrom(dumper.Packets())

	defer dumper.Stop()
	defer export.Stop()

	fmt.Println("Capturing packets, hit CTRL+C to stop")
	export.Start()
}
