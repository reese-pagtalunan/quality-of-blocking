#!/usr/bin/env bash
# Router-under-test bring-up:
#   1. enable forwarding + STRICT uRPF on the ingress interface (this is what
#      turns a blackhole route for a SOURCE into a drop — i.e. S/RTBH);
#   2. start FRR (BGP + the static discard route);
#   3. start softflowd exporting NetFlow v9 for ingress (eth1) to goflow2.
#
# CAVEAT (read lab/README.md): softflowd captures via libpcap, which sees
# packets BEFORE the kernel uRPF drop. So this lab faithfully exercises the
# pipeline + our code, but it CANNOT prove the production hardware's
# pre/post-drop accounting order. For that, swap in a Cisco node (native FNF).
set -euo pipefail

COLLECTOR_IP="${COLLECTOR_IP:-172.20.20.13}"   # goflow2 node
NETFLOW_PORT="${NETFLOW_PORT:-2055}"
INGRESS_IF="${INGRESS_IF:-eth1}"

echo "[setup] enabling IP forwarding + strict uRPF on ${INGRESS_IF}"
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w "net.ipv4.conf.${INGRESS_IF}.rp_filter=1"
# Log martians/uRPF drops so we can eyeball them in dmesg.
sysctl -w net.ipv4.conf.all.log_martians=1

echo "[setup] starting FRR"
/usr/lib/frr/frrinit.sh start || service frr start || true
sleep 2

echo "[setup] starting softflowd on ${INGRESS_IF} -> ${COLLECTOR_IP}:${NETFLOW_PORT} (NetFlow v9)"
# -v 9: NetFlow v9 ; -t maxlife=5: flush flows quickly so test windows are tight.
# -s 1: no sampling in-lab (the REAL exporters sample; we add scaling in code).
softflowd -i "${INGRESS_IF}" -n "${COLLECTOR_IP}:${NETFLOW_PORT}" -v 9 -t maxlife=5 -s 1

echo "[setup] done. softflowd running; FRR up."
