#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "include/helpers.h"

#define ETH_P_IP 0x0800 /* Internet Protocol Packet */
#define PROTO_TCP 6
#define PROTO_UDP 17

struct packetkey {
    __u32 address;
    __u16 port;
    __u16 dummy;
};

struct source_dest_key {
    struct packetkey source;
    struct packetkey dest;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct packetkey);
    __type(value, struct packetkey);
    __uint(max_entries, 1000);
} egress_mapping SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct source_dest_key);
    __type(value, struct packetkey);
    __uint(max_entries, 1000);
} ingress_mapping SEC(".maps");

SEC("tc_proxy")
int proxy_egress(struct __sk_buff *skb)
{
    void *data_end = (void *)(__u64)skb->data_end;
    void *data = (void *)(__u64)skb->data;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;

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

    //extract the port from tcp or ip headers
    __u16 source_port;
    __u16 dest_port;
    if (ip->protocol == PROTO_TCP) {
        tcp = (void *)ip + sizeof(struct iphdr);
        if ((void *)tcp + sizeof(struct tcphdr) > data_end) {
            return TC_ACT_OK;
        }
        source_port = bpf_ntohs(tcp->source);
        dest_port = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == PROTO_UDP) {
        udp = (void *)ip + sizeof(struct iphdr);
        if ((void *)udp + sizeof(struct udphdr) > data_end) {
            return TC_ACT_OK;
        }
        source_port = bpf_ntohs(udp->source);
        dest_port = bpf_ntohs(udp->dest);
    } else {
        return TC_ACT_OK;
    }

    //do we have an entry in the egress map for the dest?
    struct packetkey dest_key = {
        .address = dest,
        .port = dest_port,
    };
    struct packetkey source_key = {
        .address = source,
        .port = source_port,
    };

    // char debug_str1[] = "egress packet: %u %u";
    // bpf_trace_printk(debug_str1, sizeof(debug_str1), dest_key.address, dest_key.port);

    struct packetkey *mapped = bpf_map_lookup_elem(&egress_mapping, &dest_key);
    if (!mapped) {
        // char debug_str3[] = "egress no match: %u %u";
        // bpf_trace_printk(debug_str3, sizeof(debug_str3), dest_key.address, dest_key.port);
        return TC_ACT_OK;
    }

    char debug_str2[] = "egress mapped pkt: %u %u";
    bpf_trace_printk(debug_str2, sizeof(debug_str2), dest_key.address, dest_key.port);

    //add ingress mapping (opposite way round)
    struct source_dest_key incoming_key = {
        .source = *mapped,
        .dest = source_key,
    };
    bpf_map_update_elem(&ingress_mapping, &incoming_key, &dest_key, BPF_ANY);

    //Update the packet with the new destination
    unsigned int old_address = ip->addrs.daddr;
    ip->addrs.daddr = bpf_htonl(mapped->address);
    //Update the checksums
    signed long long ip_diff = bpf_csum_diff(&old_address, sizeof(old_address), &ip->addrs.daddr, sizeof(ip->addrs.daddr), 0);
    if (tcp) {
        unsigned short old_port = tcp->dest;
        tcp->dest = bpf_htons(mapped->port);
        signed long long tcp_diff = bpf_csum_diff(&old_port, sizeof(old_port), &tcp->dest, sizeof(tcp->dest), 0);
        bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check) , 0, ip_diff, 0);
        bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check), 0, ip_diff + tcp_diff, BPF_F_PSEUDO_HDR);
    } else if (udp) {
        unsigned short old_port = udp->dest;
        udp->dest = bpf_htons(mapped->port);
        signed long long udp_diff = bpf_csum_diff(&old_port, sizeof(old_port), &udp->dest, sizeof(udp->dest), 0);
        bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check) , 0, ip_diff, 0);
        bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, check), 0, ip_diff + udp_diff,  BPF_F_PSEUDO_HDR);
    }

    // //And redirect
    bpf_redirect(skb->ifindex, 0);
    return TC_ACT_OK;

    // bpf_clone_redirect(skb, skb->ifindex, 0);
    // return TC_ACT_SHOT;
}

SEC("tc_proxy")
int proxy_ingress(struct __sk_buff *skb)
{
    void *data_end = (void *)(__u64)skb->data_end;
    void *data = (void *)(__u64)skb->data;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;

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

    //extract the port from tcp or ip headers
    __u16 source_port;
    __u16 dest_port;
    if (ip->protocol == PROTO_TCP) {
        tcp = (void *)ip + sizeof(struct iphdr);
        if ((void *)tcp + sizeof(struct tcphdr) > data_end) {
            return TC_ACT_OK;
        }
        source_port = bpf_ntohs(tcp->source);
        dest_port = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == PROTO_UDP) {
        udp = (void *)ip + sizeof(struct iphdr);
        if ((void *)udp + sizeof(struct udphdr) > data_end) {
            return TC_ACT_OK;
        }
        source_port = bpf_ntohs(udp->source);
        dest_port = bpf_ntohs(udp->dest);
    } else {
        return TC_ACT_OK;
    }

    //do we have an entry in the ingress map for this source dest
    struct packetkey dest_key = {
        .address = dest,
        .port = dest_port,
    };
    struct packetkey source_key = {
        .address = source,
        .port = source_port,
    };
    struct source_dest_key incoming_keys = {
        .source = source_key,
        .dest = dest_key,
    };

    // char debug_str1[] = "ingress packet: %u %u";
    // bpf_trace_printk(debug_str1, sizeof(debug_str1), source_key.address, source_key.port);

    struct packetkey *mapped = bpf_map_lookup_elem(&ingress_mapping, &incoming_keys);
    if (!mapped) {
        // char debug_str4[] = "ingress no match: %u %u";
        // bpf_trace_printk(debug_str4, sizeof(debug_str4), source_key.address, source_key.port);
        return TC_ACT_OK;
    };

    char debug_str2[] = "ingress mapped pkt from: %u %u";
    bpf_trace_printk(debug_str2, sizeof(debug_str2), source_key.address, source_key.port);
    char debug_str3[] = "ingress mapped pkt to: %u %u";
    bpf_trace_printk(debug_str3, sizeof(debug_str3), mapped->address, mapped->port);

    //Update the packet with the new source
    unsigned int old_address = ip->addrs.saddr;
    ip->addrs.saddr = bpf_htonl(mapped->address);
    //Update the checksums
    signed long long ip_diff = bpf_csum_diff(&old_address, sizeof(old_address), &ip->addrs.saddr, sizeof(ip->addrs.saddr), 0);
    if (tcp) {
        unsigned short old_port = tcp->source;
        tcp->source = bpf_htons(mapped->port);
        signed long long tcp_diff = bpf_csum_diff(&old_port, sizeof(old_port), &tcp->source, sizeof(tcp->source), 0);
        bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), 0, ip_diff, 0);
        bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check), 0, ip_diff + tcp_diff, BPF_F_PSEUDO_HDR);
    } else if (udp) {
        unsigned short old_port = udp->source;
        udp->source = bpf_htons(mapped->port);
        signed long long udp_diff = bpf_csum_diff(&old_port, sizeof(old_port), &udp->source, sizeof(udp->source), 0);
        bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), 0, ip_diff, 0);
        bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, check), 0, ip_diff + udp_diff, BPF_F_PSEUDO_HDR);
    } else {
        return TC_ACT_OK;
    }

    // //And redirect
    bpf_redirect(skb->ifindex, BPF_F_INGRESS);
    return TC_ACT_OK;

    // bpf_clone_redirect(skb, skb->ifindex, BPF_F_INGRESS);
    // return TC_ACT_SHOT;
}

char __license[] SEC("license") = "Dual MIT/GPL";
