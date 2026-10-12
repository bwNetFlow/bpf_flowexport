module github.com/bwNetFlow/bpf_flowexport

go 1.25.0

require (
	github.com/bwNetFlow/flowpipeline v0.8.0-beta.0.20220513125019-53402b7ca136
	github.com/cilium/ebpf v0.22.0
	github.com/prometheus/client_golang v1.12.1
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bwNetFlow/protobuf/go v0.0.0-20211004083441-61e193b4b342 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.1 // indirect
	github.com/netsampler/goflow2 v1.1.0 // indirect
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/prometheus/common v0.33.0 // indirect
	github.com/prometheus/procfs v0.7.3 // indirect
	golang.org/x/sys v0.43.0 // indirect
	google.golang.org/protobuf v1.28.0 // indirect
)

tool github.com/cilium/ebpf/cmd/bpf2go
