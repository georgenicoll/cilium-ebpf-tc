package main

// from https://d0u9.io/use-cilium-ebpf-to-compile-and-load-tc-bpf-code/

import (
	"log"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go tc bpf/bpf.c -- -I./bpf

func InttoIP4(ipInt uint32) string {
	// need to do two bit shifting and “0xff” masking
	b0 := strconv.FormatInt(int64((ipInt>>24)&0xff), 10)
	b1 := strconv.FormatInt(int64((ipInt>>16)&0xff), 10)
	b2 := strconv.FormatInt(int64((ipInt>>8)&0xff), 10)
	b3 := strconv.FormatInt(int64((ipInt & 0xff)), 10)
	return b0 + "." + b1 + "." + b2 + "." + b3
}

const INTERFACE = "enp1s0"

func main() {
	var err error

	// Load bpf programs and maps into the kernel
	objs := tcObjects{}
	if err := loadTcObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	progFd := objs.TcMain.FD()

	intf, err := netlink.LinkByName(INTERFACE)
	if err != nil {
		log.Fatalf("cannot find %s: %v", INTERFACE, err)
	}

	attrs := netlink.QdiscAttrs{
		LinkIndex: intf.Attrs().Index, //Interface index
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}

	// declare the qdisc
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	// add the qdisc
	if err := netlink.QdiscAdd(qdisc); err != nil {
		log.Fatalf("cannot add clsact qdisc: %v", err)
	}

	//filter attributes
	filterAttrs := netlink.FilterAttrs{
		LinkIndex: intf.Attrs().Index,
		// Parent:    netlink.HANDLE_MIN_INGRESS, //direction
		Parent:   netlink.HANDLE_MIN_EGRESS,
		Handle:   netlink.MakeHandle(0, 1),
		Protocol: unix.ETH_P_ALL,
		Priority: 1,
	}

	//declare the BPF filter
	filter := &netlink.BpfFilter{
		FilterAttrs:  filterAttrs,
		Fd:           progFd,
		Name:         "hi-tc",
		DirectAction: true,
	}

	//add the filter
	if err := netlink.FilterAdd(filter); err != nil {
		log.Fatalf("cannot attach bpf object to filter: %v", err)
	}

	log.Printf("Counting packets on %s...", INTERFACE)

	//repeatedly output the map contents
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	pktCount := objs.PktCount
	for {
		select {
		case <-tick:
			log.Printf("==========")
			var (
				entries    = pktCount.Iterate()
				sourcedest tcSourcedest
				count      uint64
			)
			for entries.Next(&sourcedest, &count) {
				source := InttoIP4(sourcedest.Source)
				dest := InttoIP4(sourcedest.Dest)
				log.Printf("%s -> %s: %d", source, dest, count)
			}
			log.Printf("")
		case <-stop:
			log.Printf("Received signal stopping.")
			return
		}
	}
}
