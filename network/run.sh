#!/bin/sh

# SPDX-FileCopyrightText: 2019 Jana Iyengar, Marten Seemann
# SPDX-License-Identifier: Apache-2.0
# This file is taken from https://github.com/marten-seemann/quic-network-simulator

set -e

# We are using eth0 and eth1 as EmuFdNetDevices in ns3.
# Use promiscuous mode to allow ns3 to capture all packets.
ifconfig eth0 promisc
ifconfig eth1 promisc

# A packet arriving at eth0 destined to 10.100.0.0/16 could be routed directly to eth1,
# and a packet arriving at eth1 destined to 10.0.0.0/16 directly to eth0.
# This would allow packets to skip the ns3 simulator altogether.
# Drop those to make sure they actually take the path through ns3.
iptables -A FORWARD -i eth0 -o eth1 -j DROP
iptables -A FORWARD -i eth1 -o eth0 -j DROP
ip6tables -A FORWARD -i eth0 -o eth1 -j DROP
ip6tables -A FORWARD -i eth1 -o eth0 -j DROP

./scratch/simple-p2p --delay=15ms --bandwidth=10Mbps --queue=25 &

PID=$(jobs -p)
trap "kill -SIGINT $PID" INT
trap "kill -SIGTERM $PID" TERM
trap "kill -SIGKILL $PID" KILL
wait
