# Lightweight host image for the src/tgt nodes: nping (precise packet bursts),
# iproute2 for addressing, tcpdump/ping for inspection.
#
# Build:  docker build -t qob/traffic:latest lab/test
FROM debian:12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap iproute2 iputils-ping tcpdump bash \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
