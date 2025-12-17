FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# Install build and runtime dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    make \
    wget \
    ca-certificates \
    dnsutils \
    tcpdump \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Install Python fuzzing tools
RUN pip3 install --no-cache-dir scapy boofuzz

WORKDIR /opt

# Download vulnerable dnsmasq version
RUN wget -O dnsmasq-2.75.tar.gz http://www.thekelleys.org.uk/dnsmasq/dnsmasq-2.75.tar.gz \
    && tar -xzf dnsmasq-2.75.tar.gz

WORKDIR /opt/dnsmasq-2.75

# Build dnsmasq with AddressSanitizer enabled
RUN make clean || true \
    && make CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" \
            LDFLAGS="-fsanitize=address"

EXPOSE 53/udp
EXPOSE 53/tcp

# IMPORTANT:
# --log-queries      -> print every DNS query
# --log-facility=-  -> send logs to stdout (docker logs)
# -k / --no-daemon  -> stay in foreground so Docker can detect crashes
CMD [  "./src/dnsmasq", "-k", "--no-daemon", "--log-queries", "--log-facility=-", "--no-hosts", "--no-resolv", "--address=/#/1.2.3.4"]
