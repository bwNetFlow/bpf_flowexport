//go:build linux
// +build linux

package packetdump

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -type packet_t -tags linux bpf ./bpf/bpf.c

func htons(value uint16) uint16 {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], value)
	return binary.NativeEndian.Uint16(buf[:])
}

func decodePacket(sample []byte) (Packet, error) {
	var raw bpfPacketT
	if _, err := binary.Decode(sample, binary.NativeEndian, &raw); err != nil {
		return Packet{}, err
	}

	var srcip, dstip net.IP
	switch raw.Etype {
	case unix.ETH_P_IP:
		srcip = make(net.IP, net.IPv4len)
		binary.BigEndian.PutUint32(srcip, raw.Srcaddr)
		dstip = make(net.IP, net.IPv4len)
		binary.BigEndian.PutUint32(dstip, raw.Dstaddr)
	case unix.ETH_P_IPV6:
		srcip = make(net.IP, net.IPv6len)
		binary.BigEndian.PutUint64(srcip, raw.SrcHi)
		binary.BigEndian.PutUint64(srcip[8:], raw.SrcLo)
		dstip = make(net.IP, net.IPv6len)
		binary.BigEndian.PutUint64(dstip, raw.DstHi)
		binary.BigEndian.PutUint64(dstip[8:], raw.DstLo)
	}
	return Packet{
		SrcAddr:       srcip,
		DstAddr:       dstip,
		InIf:          raw.Inif,
		OutIf:         raw.Outif,
		Bytes:         raw.Bytes,
		Etype:         raw.Etype,
		Proto:         raw.Proto,
		Ipv6FlowLabel: raw.Ipv6Flowlabel,
		SrcPort:       raw.Srcport,
		DstPort:       raw.Dstport,
		IPTtl:         raw.Ipttl,
		IPTos:         raw.Tos,
		IcmpType:      raw.IcmpType,
		IcmpCode:      raw.IcmpCode,
		TcpFlags:      raw.TcpFlags,
		FlowDirection: raw.Direction,
		RemoteAddr:    raw.Remoteaddr,
	}, nil
}

// Link-local addresses are useless to a collector, so a global unicast address wins.
func pickSamplerAddress(addrs []net.Addr) net.IP {
	var fallback net.IP
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() {
			continue
		}
		if ipnet.IP.IsGlobalUnicast() {
			return ipnet.IP
		}
		if fallback == nil {
			fallback = ipnet.IP
		}
	}
	return fallback
}

type PacketDumper struct {
	BufSize int // Determines kernel perf map allocation. It is rounded up to the nearest multiple of the current page size.

	// SamplerAddress is picked from the interface by Setup unless it is set beforehand.
	SamplerAddress net.IP

	packets chan Packet // exported through .Packets()

	// setup
	objs  bpfObjects
	iface *net.Interface

	// start
	socket     *os.File
	perfReader *perf.Reader
}

// returns the decoded packet stream - closed chan after Stop.
func (dumper *PacketDumper) Packets() chan Packet {
	if dumper.packets != nil {
		return dumper.packets
	}
	dumper.packets = make(chan Packet)
	go func() {
		defer close(dumper.packets)
		for {
			record, err := dumper.perfReader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				log.Printf("[error] BPF packet dump: Error reading from kernel perf event reader: %s", err)
				continue
			}

			if record.LostSamples != 0 {
				log.Printf("[warning] BPF packet dump: Dropped %d samples from kernel perf buffer, consider increasing BufSize (currently %d bytes)", record.LostSamples, dumper.BufSize)
				continue
			}

			packet, err := decodePacket(record.RawSample)
			if err != nil {
				log.Printf("[error] BPF packet dump: Skipped 1 sample, error decoding raw perf event data: %s", err)
				continue
			}
			dumper.packets <- packet
		}
	}()
	return dumper.packets
}

func (dumper *PacketDumper) Setup(device string) error {
	var err error
	if dumper.iface, err = net.InterfaceByName(device); err != nil {
		return fmt.Errorf("Unable to get interface, err: %w", err)
	}

	if dumper.SamplerAddress == nil {
		addrs, err := dumper.iface.Addrs()
		if err != nil {
			return fmt.Errorf("Unable to get interface addresses, err: %w", err)
		}
		dumper.SamplerAddress = pickSamplerAddress(addrs)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("Unable to remove memlock rlimit, err: %w", err)
	}

	if err := loadBpfObjects(&dumper.objs, nil); err != nil {
		return fmt.Errorf("Unable to load BPF objects, err: %w", err)
	}

	return nil
}

func (dumper *PacketDumper) Start() error {
	if dumper.iface == nil {
		return errors.New("Start ran without init")
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("Unable to open raw socket, err: %w", err)
	}

	sll := unix.SockaddrLinklayer{
		Ifindex:  dumper.iface.Index,
		Protocol: htons(unix.ETH_P_ALL),
	}
	if err := unix.Bind(fd, &sll); err != nil {
		unix.Close(fd)
		return fmt.Errorf("Unable to bind interface to raw socket, err: %w", err)
	}

	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ATTACH_BPF, dumper.objs.PacketDump.FD()); err != nil {
		unix.Close(fd)
		return fmt.Errorf("Unable to attach BPF socket filter, err: %w", err)
	}

	if dumper.BufSize == 0 {
		// Set to a reasonably conservative value thats safe for
		// client-side pps levels.
		// Cilium docs set this to os.Getpagesize, which will return
		// 4096 bytes on any resonably modern platform. This however
		// leads to dropped samples in high load situations for dev
		// machines and containers, so the default is to increase that
		// by a factor of 2.
		dumper.BufSize = 2 * 4096
	}
	perfReader, err := perf.NewReader(dumper.objs.Packets, dumper.BufSize)
	if err != nil {
		unix.Close(fd)
		return fmt.Errorf("Unable to connect kernel perf event reader, err: %w", err)
	}

	dumper.socket = os.NewFile(uintptr(fd), "packetdump")
	dumper.perfReader = perfReader
	return nil
}

func (dumper *PacketDumper) Stop() error {
	var errs []error
	if dumper.perfReader != nil {
		errs = append(errs, dumper.perfReader.Close())
	}
	if dumper.socket != nil {
		errs = append(errs, dumper.socket.Close())
	}
	errs = append(errs, dumper.objs.Close())
	return errors.Join(errs...)
}
