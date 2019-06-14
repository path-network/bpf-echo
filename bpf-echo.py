#!/usr/bin/env python3

# Copyright 2019 Path Network, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from bcc import BPF
from pyroute2 import IPRoute
import socket
import ipaddress
import argparse
import time
import sys

parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument(
    "--ipv4",
    default="127.0.0.1",
    help="IPv4 address that will reflect packets. Disabled if empty string.",
)
parser.add_argument(
    "--ipv6",
    default="",
    help="IPv6 address that will reflect packets. Disabled if empty string.",
)
parser.add_argument(
    "--port",
    type=int,
    default=12345,
    help="TCP/UDP destination port that will reflect packets.",
)
parser.add_argument(
    "--ifname", default="lo", help="Interface the eBPF classifier will be loaded on."
)
args = parser.parse_args()

if not args.ipv4 and not args.ipv6:
    print("at least one of --ipv4 and --ipv6 has to be given", file=sys.stderr)
    exit(1)

ipr = IPRoute()

text = """
#define KBUILD_MODNAME "foo"

#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>

int echo(struct __sk_buff *skb) {
    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;

    struct ethhdr *eth = data;
    if (unlikely((void*)(eth + 1) > data_end))
        return TC_ACT_SHOT;

    if (unlikely(eth->h_proto != htons(ETH_P_IP) && eth->h_proto != htons(ETH_P_IPV6)))
        return TC_ACT_OK;

    struct iphdr *ip = (void*)(eth + 1);
    struct ipv6hdr *ip6 = (void*)(eth + 1);
    void *ip_payload;
    u8 l4_proto;
    u16 len = 0;

    if (eth->h_proto == htons(ETH_P_IP)) {
#ifdef ENABLE_IPV4
        if (unlikely((void*)(ip + 1) > data_end))
            return TC_ACT_SHOT;

        if (ip->daddr != IPV4_DEST)
            return TC_ACT_OK;

        l4_proto = ip->protocol;
        ip_payload = (void*)(ip + 1);
#else
        return TC_ACT_OK;
#endif
    } else {
#ifdef ENABLE_IPV6
        if (unlikely((void*)(ip6 + 1) > data_end))
            return TC_ACT_SHOT;

        u64 *ipdest = (void*)&ip6->daddr;
        if (ipdest[0] != IPV6_DEST_HIGH || ipdest[1] != IPV6_DEST_LOW)
            return TC_ACT_OK;

        l4_proto = ip6->nexthdr;
        ip_payload = (void*)(ip6 + 1);
#eldse
        return TC_ACT_OK;
#endif
    }

    if (unlikely(l4_proto != IPPROTO_TCP && l4_proto != IPPROTO_UDP))
        return TC_ACT_OK;

    u16 *sport = ip_payload;
    if (unlikely((void*)(sport + 1) > data_end))
        return TC_ACT_SHOT;

    u16 *dport = (void*)(sport + 1);
    if (unlikely((void*)(dport + 1) > data_end))
        return TC_ACT_SHOT;

    if (*dport != DPORT)
        return TC_ACT_OK;

    if (l4_proto == IPPROTO_TCP) {
        struct tcphdr *tcp = ip_payload;
        if (unlikely((void*)(tcp + 1) > data_end))
            return TC_ACT_SHOT;

        if (tcp->syn || tcp->fin || tcp->rst)
            return TC_ACT_OK;

        u32 tmp_seq = tcp->seq;
        tcp->seq = tcp->ack_seq;
        tcp->ack_seq = tmp_seq;
    }

    u8 tmp_mac[ETH_ALEN];
    memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, tmp_mac, ETH_ALEN);

    if (eth->h_proto == htons(ETH_P_IP)) {
        u32 tmp_ip = ip->saddr;
        ip->saddr = ip->daddr;
        ip->daddr = tmp_ip;
    } else {
        u64 tmp_ip;
        u64 *ipsrc = (void*)&ip6->saddr, *ipdest = (void*)&ip6->daddr;
        tmp_ip = ipsrc[0];
        ipsrc[0] = ipdest[0];
        ipdest[0] = tmp_ip;
        tmp_ip = ipsrc[1];
        ipsrc[1] = ipdest[1];
        ipdest[1] = tmp_ip;
    }

    u16 tmp_port = *sport;
    *sport = *dport;
    *dport = tmp_port;

    return TC_ACT_OK;
}
"""

try:
    port = socket.htons(args.port)
    idx = ipr.link_lookup(ifname=args.ifname)[0]
    cflags = ["-DDPORT={}".format(port)]

    sock4 = None
    if args.ipv4 != "":
        ipv4 = int.from_bytes(
            ipaddress.IPv4Address(args.ipv4).packed, byteorder="little"
        )
        cflags.extend(("-DENABLE_IPV4", "-DIPV4_DEST={}u".format(ipv4)))

        sock4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock4.bind((args.ipv4, args.port))
        sock4.listen(1024)

    sock6 = None
    if args.ipv6:
        ipv6 = ipaddress.IPv6Address(args.ipv6)
        ipv6_high = int.from_bytes(ipv6.packed[:8], byteorder="little")
        ipv6_low = int.from_bytes(ipv6.packed[8:], byteorder="little")
        cflags.extend(
            (
                "-DENABLE_IPV6",
                "-DIPV6_DEST_HIGH={}ull".format(ipv6_high),
                "-DIPV6_DEST_LOW={}ull".format(ipv6_low),
            )
        )

        sock6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock6.bind((args.ipv6, args.port))
        sock6.listen(1024)

    b = BPF(text=text, debug=0, cflags=cflags)
    fn = b.load_func("echo", BPF.SCHED_CLS)

    ipr.tc("add", "clsact", idx)
    ipr.tc(
        "add-filter",
        "bpf",
        idx,
        ":1",
        fd=fn.fd,
        name=fn.name,
        parent="ffff:fff3",
        classid=1,
        direct_action=True,
    )

    while True:
        time.sleep(1)

finally:
    if "idx" in locals():
        ipr.tc("del", "clsact", idx)
