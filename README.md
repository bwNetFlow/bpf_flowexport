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

## Capabilities

* `cap_sys_resource` is required to release the rlimit memlock which is
  necessary to be able to load BPF programs
* `cap_net_raw` is required to open raw sockets, to which our BPF program needs
  to attach
* `cap_perfmon` is required to create a kernel perf buffer for exporting packet
  data into user space

Full example:

```bash
sudo setcap cap_sys_resource,cap_net_raw,cap_perfmon+ep binary
```
