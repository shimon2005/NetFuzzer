FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    make \
    wget \
    ca-certificates \
    dnsutils \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir scapy boofuzz

WORKDIR /opt

RUN wget -O dnsmasq-2.75.tar.gz http://www.thekelleys.org.uk/dnsmasq/dnsmasq-2.75.tar.gz \
    && tar -xzf dnsmasq-2.75.tar.gz

WORKDIR /opt/dnsmasq-2.75

RUN make clean || true \
    && make CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" \
            LDFLAGS="-fsanitize=address"

EXPOSE 53/udp
EXPOSE 53/tcp

CMD ["sh", "-c", "./src/dnsmasq -k --no-daemon --no-hosts --no-resolv --address=/#/1.2.3.4 2>&1 | tee /tmp/dnsmasq_crash.log"]