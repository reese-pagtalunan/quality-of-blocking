#!/usr/bin/env bash
# Apply the qob-flow index template to Elasticsearch.
#
# Run this ONCE right after `containerlab deploy`, BEFORE any flow is indexed,
# so src_addr/dst_addr get the `ip` type (required for CIDR term filtering and
# the terms aggregation in qob.ingest.flow_es).
#
# Usage:  bash lab/es/bootstrap.sh [ES_URL]
set -euo pipefail

ES_URL="${1:-http://localhost:9200}"
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "[bootstrap] waiting for Elasticsearch at ${ES_URL} ..."
for i in $(seq 1 60); do
  if curl -fs "${ES_URL}/_cluster/health" >/dev/null 2>&1; then
    break
  fi
  sleep 2
  [ "$i" -eq 60 ] && { echo "ES not ready after 120s" >&2; exit 1; }
done

echo "[bootstrap] applying qob-flow index template"
curl -fs -X PUT "${ES_URL}/_index_template/qob-flow" \
  -H 'Content-Type: application/json' \
  --data-binary "@${HERE}/flow-index-template.json" \
  && echo && echo "[bootstrap] template applied."
