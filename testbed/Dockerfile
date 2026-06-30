# Reproducibility: the floating tag below is convenient for development.
# For a byte-stable archival build, pin the base image by digest:
#   FROM debian:bookworm-slim@sha256:<digest>
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    nftables \
    conntrack \
    dnsmasq \
    isc-dhcp-server \
    isc-dhcp-client \
    radvd \
    tcpdump \
    curl \
    netcat-openbsd \
    dnsutils \
    iputils-ping \
    procps \
    kmod \
    net-tools \
    python3 \
    python3-pip \
    python3-scapy \
    python3-netifaces \
    python3-psutil \
    python-is-python3 \
    hping3 \
    tcpreplay \
    nmap \
    thc-ipv6 \
    socat \
    ncat \
    snmpd \
    snmp \
    graphviz \
    build-essential \
    python3-dev \
    libnetfilter-queue-dev \
    libnfnetlink-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --break-system-packages graphviz==0.21
# NetfilterQueue: in-path IP-ID rewriting for the T6 Feistel defence
# (Gilad-Herzberg 2013 §8.3, testbed/defenses/feistel_b4.py)
RUN pip3 install --break-system-packages NetfilterQueue

WORKDIR /testbed

COPY . /testbed/

# Stamp the image with the build time so entrypoint.sh can warn users
# running a stale image (the testbed source is COPYed in here, so any
# edit on the host requires a rebuild to take effect).
RUN date -u +'%Y-%m-%dT%H:%M:%SZ' > /testbed/BUILD_INFO \
    && chmod +x setup.sh teardown.sh entrypoint.sh \
    b4/*.sh aftr/*.sh scripts/*.sh \
    aftr/*.py \
    attack_tools/*.py \
    attack_tools/nat/*.py \
    attack_tools/tunnel/*.py \
    attack_tools/dns/*.py \
    attack_tools/infra/*.py \
    && mkdir -p /testbed/pcaps \
    && mkdir -p /testbed/attack_trees/results

ENTRYPOINT ["/testbed/entrypoint.sh"]
