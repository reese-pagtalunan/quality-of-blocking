#!/usr/bin/env bash
# Inject / remove a SOURCE-based RTBH block via ExaBGP, mirroring what
# bhr-client-exabgp does in production.
#
# Usage (run inside the exabgp container):
#   ./blackhole.sh block   10.0.1.66
#   ./blackhole.sh unblock 10.0.1.66
#
# Announces SRC/32 with next-hop 192.0.2.1 (the router's discard route) and the
# blackhole community 65535:666. The router recursively resolves to its
# blackhole route; strict uRPF then drops traffic FROM that source.
set -euo pipefail

ACTION="${1:-}"
IP="${2:-10.0.1.66}"
DISCARD_NH="192.0.2.1"
COMMUNITY="65535:666"

case "${ACTION}" in
  block)
    exabgpcli announce route "${IP}/32" next-hop "${DISCARD_NH}" community "[${COMMUNITY}]"
    echo "[blackhole] BLOCKED ${IP}/32 (community ${COMMUNITY}, nh ${DISCARD_NH})"
    ;;
  unblock)
    exabgpcli withdraw route "${IP}/32" next-hop "${DISCARD_NH}" community "[${COMMUNITY}]"
    echo "[blackhole] UNBLOCKED ${IP}/32"
    ;;
  *)
    echo "usage: $0 {block|unblock} <ip>" >&2
    exit 2
    ;;
esac

echo "[blackhole] current adj-rib-out:"
exabgpcli show adj-rib out || true
