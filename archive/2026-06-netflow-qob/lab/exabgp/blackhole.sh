#!/usr/bin/env bash
# Inject / remove a SOURCE-based RTBH block via ExaBGP, mirroring what
# bhr-client-exabgp does in production.
#
# Works by appending exabgp text-API commands to the file that exabgp tails
# (see exabgp.conf "watch-commands").
#
# Usage (run inside the exabgp container):
#   ./blackhole.sh block   10.0.1.66
#   ./blackhole.sh unblock 10.0.1.66
set -euo pipefail

ACTION="${1:-}"
IP="${2:-10.0.1.66}"
DISCARD_NH="192.0.2.1"
COMMUNITY="65535:666"
CMD_FILE="/var/run/exabgp/commands.txt"

case "${ACTION}" in
  block)
    echo "announce route ${IP}/32 next-hop ${DISCARD_NH} community [${COMMUNITY}]" >> "${CMD_FILE}"
    echo "[blackhole] BLOCKED ${IP}/32 (community ${COMMUNITY}, nh ${DISCARD_NH})"
    ;;
  unblock)
    echo "withdraw route ${IP}/32 next-hop ${DISCARD_NH} community [${COMMUNITY}]" >> "${CMD_FILE}"
    echo "[blackhole] UNBLOCKED ${IP}/32"
    ;;
  *)
    echo "usage: $0 {block|unblock} <ip>" >&2
    exit 2
    ;;
esac
