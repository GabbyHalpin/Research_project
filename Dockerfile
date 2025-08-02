# 1) Base image
FROM ubuntu:22.04

WORKDIR /sim

# Install dependencies
RUN apt-get update -y && apt-get install -y && apt-get install vim -y\
    build-essential cmake git wget curl python3 python3-pip \
    libglib2.0-dev libevent-dev \
    ca-certificates

# required dependencies for Shadow
RUN apt-get install -y \
    cmake \
    findutils \
    libclang-dev \
    libc-dbg \
    libglib2.0-0 \
    libglib2.0-dev \
    make \
    netbase \
    python3 \
    python3-networkx \
    xz-utils \
    util-linux \
    gcc \
    g++ &&\
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
    . /root/.cargo/env && \
    export PATH="/root/.cargo/bin:$PATH" && \
    git clone https://github.com/shadow/shadow.git &&\
    cd shadow &&\
    ./setup build --clean --test --prefix=/usr/local && \
    ./setup install && \
    cd ../

# Download TGen for traffic generation used in Shadow
RUN apt-get install cmake libglib2.0-dev libigraph-dev -y &&\
    git clone https://github.com/shadow/tgen.git && \
    cd tgen && \
    mkdir build && cd build && \
    cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local && \
    make && \
    make install

# Download OnionTrace for Tornettools
RUN apt-get install cmake libglib2.0-dev libigraph-dev -y &&\
    git clone https://github.com/shadow/oniontrace.git && \
    cd oniontrace && \
    mkdir build && cd build && \
    cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local && \
    make && \
    make install

# Install tornettools from accurate large scale simulations
RUN git clone https://github.com/shadow/tornettools.git && \
    cd tornettools &&\
    pip3 install -r requirements.txt && \
    pip3 install --ignore-installed . &&\
    cd ../

# # fetch data for the tornettools network
RUN wget https://collector.torproject.org/archive/relay-descriptors/consensuses/consensuses-2025-04.tar.xz &&\
    wget https://collector.torproject.org/archive/relay-descriptors/server-descriptors/server-descriptors-2025-04.tar.xz &&\
    wget https://metrics.torproject.org/userstats-relay-country.csv &&\
    wget https://collector.torproject.org/archive/onionperf/onionperf-2025-04.tar.xz &&\
    wget -O bandwidth-2025-04.csv "https://metrics.torproject.org/bandwidth.csv?start=2025-04-01&end=2025-04-30" &&\
    tar xaf consensuses-2025-04.tar.xz &&\
    tar xaf server-descriptors-2025-04.tar.xz &&\
    tar xaf onionperf-2025-04.tar.xz
    
RUN git clone https://github.com/tmodel-ccs2018/tmodel-ccs2018.github.io.git


#installing the tor browswer
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone && \
    apt-get update && \
    apt-get install -y autotools-dev autoconf automake libtool && \
    apt-get install -y openssl libssl-dev libevent-dev build-essential zlib1g zlib1g-dev && \
    git clone https://git.torproject.org/tor.git && \
    cd tor && \
    ./autogen.sh && \
    ./configure --prefix=/usr/local --disable-asciidoc --disable-unittests --disable-manpage --disable-html-manual && \
    make -j$(nproc) && \
    make install &&\
    apt-get install faketime dstat procps xz-utils -y &&\
    export PATH=${PATH}:`pwd`/tor/src/core/or:`pwd`/tor/src/app:`pwd`/tor/src/tools

#install dependency obfs4proxy
RUN wget https://dl.google.com/go/go1.24.5.linux-amd64.tar.gz &&\
    tar -C /usr/local -xzf go1.24.5.linux-amd64.tar.gz &&\
    export PATH=$PATH:/usr/local/go/bin &&\
    git clone https://gitlab.com/yawning/obfs4.git &&\
    cd obfs4 &&\
    go build -o obfs4proxy/obfs4proxy ./obfs4proxy &&\
    cp ./obfs4proxy/obfs4proxy /usr/local/bin

RUN pip install --upgrade networkx

# Installing Arti with Shadow support
RUN apt-get update -y && apt-get install libsqlite3-dev -y &&\
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
    . /root/.cargo/env && \
    export PATH="/root/.cargo/bin:$PATH" && \
    git clone https://gitlab.torproject.org/tpo/core/arti.git &&\
    cd arti &&\
    # Build arti-extra with additional features for shadow
    cargo build --locked --verbose \
        --target x86_64-unknown-linux-gnu \
        -p arti -p tor-circmgr \
        --bin arti \
        --features full,restricted-discovery,arti-client/keymgr,onion-service-service,vanguards,ctor-keystore &&\
    mv target/x86_64-unknown-linux-gnu/debug/arti target/x86_64-unknown-linux-gnu/debug/arti-extra &&\
    # Build vanilla arti for shadow
    cargo build --locked --verbose --target x86_64-unknown-linux-gnu -p arti &&\
    # Also build release version for general use
    cargo build -p arti --release &&\
    cd ../ &&\
    # Copy the release version to system path for general use
    cp arti/target/release/arti /usr/local/bin/arti &&\
    # Create directory structure that shadow expects
    mkdir -p /shadow/target/x86_64-unknown-linux-gnu/debug &&\
    # Copy shadow-specific builds to expected locations
    cp arti/target/x86_64-unknown-linux-gnu/debug/arti-extra /shadow/target/x86_64-unknown-linux-gnu/debug/arti-extra &&\
    cp arti/target/x86_64-unknown-linux-gnu/debug/arti /shadow/target/x86_64-unknown-linux-gnu/debug/arti

# # Copying necessary files into /sim folder
# COPY shadow_tor.yaml .
COPY shadow_expanded.yaml .
# COPY arti.toml .
COPY tgen.client.graphml.xml .
COPY tgen.torclient.graphml.xml .
COPY tgen.server.graphml.xml .


# 6) Default entrypoint
ENTRYPOINT ["bash"]
