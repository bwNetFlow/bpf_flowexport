package main

import (
	"fmt"
	"os"

	"github.com/bwNetFlow/bpf_flowexport/bpf"
	"github.com/bwNetFlow/bpf_flowexport/flowexport"
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

	// setup bpf dumping
	dumper := &bpf.PacketDumper{}
	err := dumper.Setup(device)
	if err != nil {
		fmt.Println(err)
	}
	err = dumper.Start()
	if err != nil {
		fmt.Println(err)
	}
	defer dumper.Stop()

	// setup flow export from the dumped packets
	fmap, err := flowexport.NewFlowExporter("30m", "15s")
	if err != nil {
		fmt.Println(err)
	}
	fmap.Start()
	defer fmap.Stop()

	go fmap.ConsumeFrom(dumper.Packets())

	for flow := range fmap.Flows {
		fmt.Printf("%s\n", flow)
	}
}
