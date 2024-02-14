#!/bin/bash
INTERFACE=enp1s0
#INTERFACE=lo
echo "= ingress filters on $INTERFACE:"
tc filter show dev $INTERFACE ingress
echo "= removing all filters..."
sudo tc filter delete dev $INTERFACE ingress
echo "= ingress filters on $INTERFACE now:"
tc filter show dev $INTERFACE ingress
echo "---"
echo "= egress filters on $INTERFACE:"
tc filter show dev $INTERFACE egress
echo "= removing all filters..."
sudo tc filter delete dev $INTERFACE egress
echo "= egress filters on $INTERFACE now:"
tc filter show dev $INTERFACE egress
echo "---"
echo "= qdiscs on $INTERFACE:"
tc qdisc show dev $INTERFACE
echo "= Removing qdisc "
sudo tc qdisc delete dev $INTERFACE parent ffff:fff1
echo "= qdiscs on $INTERFACE now:"
tc qdisc show dev $INTERFACE
echo "---"
