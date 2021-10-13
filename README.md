This repo links a packet dump from BPF with a simple Flow Exporter. It uses the
format outlined by github.com/bwNetFlow/protobuf as an output, which is very
similar to github.com/netsampler/goflow2 format. I.e., no actual Netflow or
IPFIX is going on here.

At the moment, it does not support sampling and uses classic inactive/active
timeouts to decide when to export flows from its cache.
