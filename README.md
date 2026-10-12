# BPF Export
This repo implements a packet dump from BPF and couples that with one of two applications:

## Flow Exporter
This exporter uses the format outlined by github.com/bwNetFlow/protobuf as an
output, which is very similar to github.com/netsampler/goflow2 format. I.e., no
actual Netflow or IPFIX is being generated.

At the moment, it does not support sampling and uses classic inactive/active
timeouts to decide when to export flows from its cache.

This is chiefly used by [bwnet's
flowpipeline](https://github.com/bwNetFlow/flowpipeline) to implement the `bpf`
segment as datasource.

## Prometheus Exporter
This exporter exposes a prometheus exporter endpoint at `:9999/metrics` with
some simple proof of concept metrics. This is generated solely on packet
headers and thus could be used to calculate statistics which would be impossible
by using kernel counters such as:

* inter packet arrivel times for specific flows
* micropeaks and burstiness of traffic
* traffic class analysis

However, the current version just exports packet and byte counts by etype and
protocol number.

## Requirements

* Linux 4.18 or newer

## Capabilities

Requires root, or the following capabilities:

| Kernel      | Capabilities                                          |
|-------------|-------------------------------------------------------|
| 5.11 or newer | `cap_bpf`, `cap_perfmon`, `cap_net_raw`              |
| 5.8 - 5.11 | `cap_bpf`, `cap_perfmon`, `cap_net_raw`, `cap_sys_resource` |
| older       | `cap_sys_admin`, `cap_net_raw`                        |

* `cap_bpf` loads the BPF program and creates its maps.
* `cap_perfmon` opens the perf buffer that carries packet headers to user space.
* `cap_net_raw` opens the raw socket the program attaches to.

Example:

```bash
sudo setcap cap_bpf,cap_perfmon,cap_net_raw+ep binary
```

### Debian and Ubuntu: `perf_event_paranoid`

Debian and Ubuntu kernels have `kernel.perf_event_paranoid` levels at which `cap_perfmon` is
not allowed to open the perf buffer. This leades to the error:

```
Unable to connect kernel perf event reader, err: failed to create perf ring for CPU 0: can't create perf event: permission denied
```

Check the level with `sysctl kernel.perf_event_paranoid`. If it is 3 or
higher, either lower it to 2 using:

```bash
# temporarily
sudo sysctl kernel.perf_event_paranoid=2
# or persist across reboots
echo 'kernel.perf_event_paranoid = 2' | sudo tee /etc/sysctl.d/60-perf-event-paranoid.conf
```

or grant `cap_sys_admin` instead of `cap_perfmon`, or run as root.

## Building

The compiled BPF objects (`packetdump/bpf_bpf{el,eb}.{go,o}`) are committed, so
a plain `go build ./...` needs only Go. Changing `packetdump/bpf/bpf.c` also requires
`clang`, `llvm` and `libbpf`. These can be installed using:

```bash
sudo apt install clang llvm libbpf-dev
```

## Testing

```bash
go test -race ./...
```

The end-to-end test injects packets on `lo` and checks every decoded field and can be executed using:

```bash
go test -c -race -o packetdump.test ./packetdump
sudo ./packetdump.test -test.run TestEndToEndLoopback -test.v
```
