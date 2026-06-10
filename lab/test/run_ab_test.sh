#!/usr/bin/env bash
# Drive the step-#2 A/B test end to end against the running containerlab.
#
#   Phase A (no block): send a burst, confirm it FORWARDS and shows up in ES.
#   Phase B (blocked):  block the source via ExaBGP, send the SAME burst,
#                       confirm it DROPS and check whether it still shows in ES.
#
# Read the result with the decision table in lab/README.md.
#
# Prereqs: lab deployed (sudo containerlab deploy -t lab/topology.clab.yml),
#          ES reachable at localhost:9200, python deps installed (.[es]).
set -euo pipefail

LAB="qob-rtbh"
SRC_C="clab-${LAB}-src"
TGT_C="clab-${LAB}-tgt"
EXABGP_C="clab-${LAB}-exabgp"
ROUTER_C="clab-${LAB}-router"

SRC_IP="10.0.1.66"
TGT_IP="10.0.2.66"
COUNT="${COUNT:-50000}"     # send enough to beat sampling noise
RATE="${RATE:-5000}"
DPORT="${DPORT:-22}"
SPORT="${SPORT:-40001}"     # fixed src port → isolate this flow in ES
ESURL="${ESURL:-http://localhost:9200}"

send_burst () {
  echo ">> sending ${COUNT} TCP pkts ${SRC_IP}:${SPORT} -> ${TGT_IP}:${DPORT}"
  docker exec "${SRC_C}" nping --tcp -p "${DPORT}" -g "${SPORT}" --tos 0x08 \
      -c "${COUNT}" --rate "${RATE}" "${TGT_IP}" >/dev/null || true
}

show_drops () {
  echo ">> router uRPF/martian drops (dmesg tail):"
  docker exec "${ROUTER_C}" sh -c "dmesg | grep -i martian | tail -n 3" || true
  echo ">> router route for ${SRC_IP} (should be blackhole in Phase B):"
  docker exec "${ROUTER_C}" sh -c "ip route get ${SRC_IP} 2>/dev/null || true"
}

echo "############ Bootstrap: ensure ES index template is applied ############"
bash "$(dirname "$0")/../es/bootstrap.sh" "${ESURL}"

echo "############ PHASE A — baseline (no block) ############"
send_burst
sleep 8   # let softflowd flush (maxlife=5) + ElastiFlow index
python3 "$(dirname "$0")/verify.py" --es-url "${ESURL}" --src "${SRC_IP}" --minutes 3 --label "phase A"

echo
echo "############ Injecting RTBH block for ${SRC_IP} ############"
docker exec "${EXABGP_C}" /blackhole.sh block "${SRC_IP}"
sleep 3
show_drops

echo
echo "############ PHASE B — blocked ############"
send_burst
sleep 8
show_drops
python3 "$(dirname "$0")/verify.py" --es-url "${ESURL}" --src "${SRC_IP}" --minutes 3 --label "phase B"

echo
echo "############ Cleanup — withdraw block ############"
docker exec "${EXABGP_C}" /blackhole.sh unblock "${SRC_IP}"

cat <<'EOF'

================= INTERPRET =================
 Phase A shows flow for the source         -> exporter/pipeline works.
 Phase B traffic is DROPPED (route=blackhole, martian logs) AND:
   * still shows ~same flow in ES  -> accounting BEFORE drop  -> Option 1 viable
   * shows ~zero flow in ES        -> accounting AFTER drop   -> pivot (Flowspec/sinkhole)

 REMINDER: softflowd taps via pcap (pre-drop), so in THIS open-source lab
 Phase B will typically still show flow. That validates the pipeline + code,
 NOT the production hardware's accounting order. Use a Cisco node (native FNF)
 or TAC/docs to settle the hardware question. See lab/README.md.
============================================
EOF
