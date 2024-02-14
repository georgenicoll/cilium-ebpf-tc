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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go tc ../bpf/proxy-bpf.c -- -I../bpf

func InttoIP4(ipInt uint32) string {
	// need to do two bit shifting and “0xff” masking
	b0 := strconv.FormatInt(int64((ipInt>>24)&0xff), 10)
	b1 := strconv.FormatInt(int64((ipInt>>16)&0xff), 10)
	b2 := strconv.FormatInt(int64((ipInt>>8)&0xff), 10)
	b3 := strconv.FormatInt(int64((ipInt & 0xff)), 10)
	return b0 + "." + b1 + "." + b2 + "." + b3
}

func IP4toInt(b0 int64, b1 int64, b2 int64, b3 int64) uint32 {
	return uint32(b0<<24 + b1<<16 + b2<<8 + b3)
}

const INTERFACE = "enp1s0"

// const INTERFACE = "lo"

func main() {
	var err error

	// Load bpf programs and maps into the kernel
	objs := tcObjects{}
	if err := loadTcObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	egressFd := objs.ProxyEgress.FD()
	ingressFd := objs.ProxyIngress.FD()

	intf, err := netlink.LinkByName(INTERFACE)
	if err != nil {
		log.Fatalf("cannot find %s: %v", INTERFACE, err)
	}

	qdiscAttrs := netlink.QdiscAttrs{
		LinkIndex: intf.Attrs().Index, //Interface index
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}

	// declare the qdisc
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: qdiscAttrs,
		QdiscType:  "clsact",
	}

	// add the qdisc
	if err := netlink.QdiscAdd(qdisc); err != nil {
		log.Fatalf("cannot add clsact egress qdisc: %v", err)
	}

	//filter attributes
	egressFilterAttrs := netlink.FilterAttrs{
		LinkIndex: intf.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}
	ingressFilterAttrs := netlink.FilterAttrs{
		LinkIndex: intf.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}

	//declare the BPF filters
	egressFilter := &netlink.BpfFilter{
		FilterAttrs:  egressFilterAttrs,
		Fd:           egressFd,
		Name:         "egress-tc",
		DirectAction: true,
	}
	ingressFilter := &netlink.BpfFilter{
		FilterAttrs:  ingressFilterAttrs,
		Fd:           ingressFd,
		Name:         "ingress-tc",
		DirectAction: true,
	}

	//add the filters
	if err := netlink.FilterAdd(egressFilter); err != nil {
		log.Fatalf("cannot attach bpf object to egress filter: %v", err)
	}
	if err := netlink.FilterAdd(ingressFilter); err != nil {
		log.Fatalf("cannot attach bpf object to ingress filter: %v", err)
	}

	//set up the egress mapping
	destKey := tcPacketkey{
		Address: IP4toInt(10, 0, 0, 138),
		Port:    12345,
	}
	forwardingKey := tcPacketkey{
		Address: IP4toInt(10, 0, 0, 138),
		Port:    23456,
	}
	log.Printf("DestKey: %v", destKey)
	log.Printf("ForwardingKey: %v", destKey)
	objs.EgressMapping.Put(destKey, forwardingKey)

	//repeatedly output the map contents
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	egressMapping := objs.EgressMapping
	ingressMapping := objs.IngressMapping
	for {
		select {
		case <-tick:
			var (
				egressEntries  = egressMapping.Iterate()
				egressKey      tcPacketkey
				egressValue    tcPacketkey
				ingressEntries = ingressMapping.Iterate()
				ingressKey     tcSourceDestKey
				ingressValue   tcPacketkey
			)
			log.Printf("== Egress ==")
			for egressEntries.Next(&egressKey, &egressValue) {
				dest_address := InttoIP4(egressKey.Address)
				dest_port := egressKey.Port
				mapping_address := InttoIP4(egressValue.Address)
				mapping_port := egressValue.Port
				log.Printf("%s[%d] -> %s[%d]",
					dest_address,
					dest_port,
					mapping_address,
					mapping_port,
				)
			}
			log.Printf("== Ingress ==")
			for ingressEntries.Next(&ingressKey, &ingressValue) {
				ingress_source_address := InttoIP4(ingressKey.Source.Address)
				ingress_source_port := ingressKey.Source.Port
				ingress_dest_address := InttoIP4(ingressKey.Dest.Address)
				ingress_dest_port := ingressKey.Dest.Port
				mapped_address := InttoIP4(ingressValue.Address)
				mapped_port := ingressValue.Port
				log.Printf("%s[%d]: %s[%d] -> %s[%d]",
					ingress_source_address,
					ingress_source_port,
					ingress_dest_address,
					ingress_dest_port,
					mapped_address,
					mapped_port,
				)
			}
			log.Printf("")
		case <-stop:
			log.Printf("Received signal stopping.")
			return
		}
	}
}
