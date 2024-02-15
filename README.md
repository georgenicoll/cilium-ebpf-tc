# Playing with cilium ebpf to add a tc filter

## Setup

See [bpf/README.md](bpf/README.md) for setting up kernel source and generating the bpf headers.
Instructions are for ubuntu but should be easy to adapt to other distros.

## tc ingress/egress packet monitor

### Code

An ebpf filter [bpf/packet-monitor-bpf.c](bpf/packet-monitor-bpf.c) is added to the kernel tc extension point.
This records information about the incoming/outgoing packets (depending on where the user space program
places the filter).  Packet information is recorded in an ebpf map.

User space code [packet-monitor/main.go](packet-monitor/main.go) repeatedly reads and outputs the contents of the map.

### Running

Run [packet-monitor/build-and-run.sh](packet-monitor/build-and-run.sh) to:

1. build the ebpf object code (using bpf2go) and generate go 'headers' (tc_bpf*.go files)
2. build the go program
3. run the go program
4. when finished, run [remove-filters-and-qdisc.sh](remove-filters-and-qdisc.sh) to remove the filters and qdisc

[packet-monitor/main.go](packet-monitor/main.go) sets up a qdisc, adds it to the interface (change this by
editing the INTERFACE constant in main.go), adds the ebpf program as a tc filter and then outputs the contents of the
ebpf map from userspace every second.

## tc ingress/egress proxy

### Code

An ebpf filter [bpf/proxy-bpf.c](bpf/proxy-bpf.c) containing egress and ingress programs to be added to the kernel tc
extension points.

The egress program (proxy_egress) checks an epf map (set up by the user space program) when it receives a packet.  The ebpf map
contains entries from egress destination (ipv4)address/port to proxied address/port.  If an entry is found for the packet's
destination address/port, then the address/port in the the packet is updated to the proxied address/port and an entry is pushed
into the ingress map to allow correct routing of packets back from the proxy.

The ingress program (proxy_ingress) looks for an entry matching the packet's source address/port and destination address/port and
updates the incoming packet's source address/port to make it look like it came from the original destination address/port if one
is found.

User space code [proxy/main.go](proxy/main.go) installs a qdisc, installs both egress and ingress epbf programs as direct action filters
and registers an egress mapping (currently the code add a mapping from 10.0.0.10:12345 to 10.0.0.138:23456 see
[proxy/main.go](proxy/main.go#L105)).

### Running

Run [proxy/build-and-run.sh](proxy/build-and-run.sh) to:

1. build the ebpf object code (using bpf2go) and generate go 'headers' (tc_bpf*.go files)
2. build the go program
3. run the go program
4. when finished, run [remove-filters-and-qdisc.sh](remove-filters-and-qdisc.sh) to remove the filters and qdisc

[proxy/main.go](proxy/main.go) sets up a qdisc, adds it to the interface (change this by editing the INTERFACE constant
in main.go), adds the 2 ebpf programs as egress and ingress tc filters, adds an entry into the egress map and then repeatedly
outputs the contents of the egress and ingress maps.

## Removing filters/epbf programs

Run [remove-filters-and-qdisc.sh](remove-filters-and-qdisc.sh) to:

1. Remove the tc filter(s) and qdisc added by the run script.
