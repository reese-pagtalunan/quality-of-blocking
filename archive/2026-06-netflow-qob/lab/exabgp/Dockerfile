# ExaBGP image built from pip (pure Python → reliable + arm64-native).
# Stands in for bhr-client-exabgp: announces/withdraws RTBH routes to FRR.
#
# Build:  docker build -t qob/exabgp:latest lab/exabgp
FROM python:3.11-slim

RUN pip install --no-cache-dir exabgp==4.2.22 \
    && mkdir -p /var/run/exabgp /etc/exabgp

# Bind-mounted by containerlab at deploy; copies are fallbacks.
COPY exabgp.conf /etc/exabgp/exabgp.conf
COPY blackhole.sh /blackhole.sh
RUN chmod +x /blackhole.sh

# Create the command FIFO-file that exabgp tails, then run exabgp.
CMD ["sh", "-c", "mkdir -p /var/run/exabgp && : > /var/run/exabgp/commands.txt && exec exabgp /etc/exabgp/exabgp.conf"]
