#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/swab.h>
#include <sys/socket.h>
#include "include/helpers.h"

#define ETH_P_IP 0x0800 /* Internet Protocol Packet */

struct sourcedest {
    __u32 source;
    __u32 dest;
    __u32 port;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct sourcedest);
    __type(value, __u64);
    __uint(max_entries, 1000);
} pkt_count SEC(".maps");

SEC("tc_prog")
int tc_main(struct __sk_buff *skb)
{
    void *data_end = (void *)(__u64)skb->data_end;
    void *data = (void *)(__u64)skb->data;
    struct ethhdr *eth;
    struct iphdr *ip;

    if (skb->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return TC_ACT_OK;

    ip = data + sizeof(struct ethhdr);
    if ((void *)ip + sizeof(struct iphdr) > data_end)
        return TC_ACT_OK;

    __u32 source = bpf_ntohl(ip->addrs.saddr);
    __u32 dest = bpf_ntohl(ip->addrs.daddr);
    __u32 port = 0;
    struct sourcedest key = {
        .source = source,
        .dest = dest,
        .port = port,
    };
    __u64 *count = bpf_map_lookup_elem(&pkt_count, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 value = 1;
        bpf_map_update_elem(&pkt_count, &key, &value, BPF_ANY);
    }

    char hello_str[] = "hello pkt ipv4: %u";
    bpf_trace_printk(hello_str, sizeof(hello_str), &skb->remote_ip4);
    return TC_ACT_OK;
}

char __license[] SEC("license") = "Dual MIT/GPL";
