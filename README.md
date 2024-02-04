# Playing with cilium ebpf to add a tc filter

## tc ingress/egress packet monitor

An ebpf filter [bpf/bpf.c](bpf/bpf.c) is added to the kernel tc extension point.
This records information about the incoming/outgoing packets (depending on
where the user space program places the filter).  Packet information is recorded in
an ebpf map.

User space code [main.go](main.go) repeatedly reads and outputs the contents of the map.

### Setup

See [bpf/README.md](bpf/README.md) for setting up kernel source and generating the bpf headers.
Instructions are for ubuntu but should be easy to adapt to other distros.

### Running

Run [build-and-run.sh](build-and-run.sh) to:

1. build the ebpf object code (using bpf2go) and generate go 'headers' (tc_bpf*.go files)
2. build the go program
3. run the go program

[main.go](main.go) sets up a qdisc, adds it to the interface (change this by editing the INTERFACE constant in main.go)
as a tc filter and then outputs the contents of the ebpf map from userspace.

Run [remove-filter-and-qdisc.sh](remove-filter-and-qdisc.sh) to:

1. Remove the tc filter and qdisc added by the run script.
