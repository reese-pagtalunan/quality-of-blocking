# Router-under-test image: FRR (BGP + RTBH) + softflowd (NetFlow v9 export)
# + iproute2/tcpdump for uRPF and inspection.
#
# Build:  docker build -t qob/rtbh-router:latest lab/router
FROM debian:12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        frr frr-pythontools \
        softflowd \
        iproute2 iputils-ping tcpdump bash procps \
    && rm -rf /var/lib/apt/lists/*

# FRR config is bind-mounted by containerlab; copies here are fallbacks.
COPY frr.conf /etc/frr/frr.conf
COPY daemons /etc/frr/daemons
COPY setup.sh /setup.sh
RUN chmod +x /setup.sh

# Keep the container alive; containerlab runs setup.sh via `exec`.
CMD ["sleep", "infinity"]
