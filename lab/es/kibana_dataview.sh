#!/usr/bin/env bash
# Create the Kibana data view for the lab flow index so you can use Discover /
# Lens immediately. Idempotent-ish: ignores "already exists" errors.
#
# Usage:  bash lab/es/kibana_dataview.sh [KIBANA_URL]
set -euo pipefail

KBN_URL="${1:-http://localhost:5601}"

echo "[kibana] waiting for Kibana at ${KBN_URL} ..."
for i in $(seq 1 90); do
  status="$(curl -s -o /dev/null -w '%{http_code}' "${KBN_URL}/api/status" || true)"
  [ "${status}" = "200" ] && break
  sleep 2
  [ "$i" -eq 90 ] && { echo "Kibana not ready after 180s" >&2; exit 1; }
done

echo "[kibana] creating data view qob-flow-*"
curl -s -X POST "${KBN_URL}/api/data_views/data_view" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -d '{"data_view":{"title":"qob-flow-*","name":"QoB flows","timeFieldName":"@timestamp"}}' \
  && echo && echo "[kibana] done — open ${KBN_URL}/app/discover"
