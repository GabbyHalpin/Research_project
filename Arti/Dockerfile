FROM ubuntu:22.04 AS base
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ENV DEBIAN_FRONTEND=noninteractive

# Get basic packages
RUN apt-get update && apt-get install -y apt-utils git sudo
RUN apt-get install -y locales
RUN apt-get update -y && apt-get install -y && apt-get install vim -y \
build-essential cmake git wget curl python3 python3-pip \
libglib2.0-dev libevent-dev \
    ca-certificates
RUN apt-get update && apt-get install -y tzdata
RUN dpkg-reconfigure locales
RUN dpkg-reconfigure tzdata

# Build shadow
FROM base AS build-shadow
WORKDIR /root/src
RUN git clone https://github.com/shadow/shadow.git
WORKDIR /root/src/shadow
ENV CC=gcc
ENV CXX=g++
ENV CONTAINER=ubuntu:22.04
ENV BUILDTYPE=release
ENV RUSTPROFILE=minimal
RUN ci/container_scripts/install_deps.sh
RUN ci/container_scripts/install_extra_deps.sh
ENV PATH="/root/.cargo/bin:${PATH}"
RUN ./setup build --jobs `nproc` --prefix /opt --clean
RUN ./setup install

# Build tgen
FROM base AS build-tgen
RUN apt-get update && apt-get install -y \
  cmake \
  libglib2.0-0 \
  libglib2.0-dev \
  libigraph-dev
WORKDIR /root/src
RUN git clone https://github.com/shadow/tgen.git
WORKDIR /root/src/tgen
WORKDIR /root/src/tgen/build
RUN cmake .. -DCMAKE_INSTALL_PREFIX=/opt
RUN make -j`nproc`
RUN make install

# Build oniontrace
FROM base AS build-oniontrace
RUN apt-get update && apt-get install -y \
  cmake \
  libglib2.0-0 \
  libglib2.0-dev
WORKDIR /root/src
RUN git clone https://github.com/shadow/oniontrace.git
WORKDIR /root/src/oniontrace/build
RUN cmake .. -DCMAKE_INSTALL_PREFIX=/opt
RUN make -j`nproc`
RUN make install

# Build tor
FROM base AS build-tor
#COPY tor-gwf-0.4.7.10.tar /root/src/tor-gwf-0.4.7.10.tar
RUN apt-get update && apt-get install -y \
  autoconf \
  automake \
  gcc \
  make \
  libevent-dev \
  openssl \
  libssl-dev \
  zlib1g-dev \
  libpsl-dev \
  libpsl5
WORKDIR /root/src
RUN git clone https://git.torproject.org/tor.git
WORKDIR /root/src/tor
RUN bash autogen.sh
ENV LIBS=-lpsl
RUN ./configure \
  --prefix=/opt \
  --disable-unittests \
  --disable-asciidoc \
  --disable-manpage \
  --disable-html-manual \
  --disable-gcc-hardening \
  --disable-linker-hardening \
  --disable-fragile-hardening \
  --disable-expensive-hardening \
  --disable-seccomp \
  --disable-system-torrc \
  --disable-dependency-tracking \
  --disable-lzma \
  --disable-zstd \
  --enable-pic
RUN make -j`nproc`
RUN make install

FROM base AS build-tornettools
RUN apt-get update && apt-get install -y \
  git \
  python3 \
  python3-pip \
  python3-venv
# Set up our python venv
ENV PYVENV=/opt
RUN python3 -m venv $PYVENV
ENV PATH=$PYVENV/bin:$PATH
# tornettools
WORKDIR /opt/src
RUN git clone https://github.com/shadow/tornettools.git
WORKDIR /opt/src/tornettools
RUN pip3 install -r requirements.txt
RUN pip3 install -I .
# tgentools (needed for parsing)
WORKDIR /opt/src
RUN git clone https://github.com/shadow/tgen.git
WORKDIR /opt/src/tgen/tools
RUN pip3 install -r requirements.txt
RUN pip3 install -I .
# oniontracetools (needed for parsing)
WORKDIR /opt/src
RUN git clone https://github.com/shadow/oniontrace.git
WORKDIR /opt/src/oniontrace/tools
RUN pip3 install -r requirements.txt
RUN pip3 install -I .
# we also need the zimply python module for the wikipedia server
RUN pip3 install zimply


FROM base AS build-obfs4proxy
RUN apt-get update && apt-get install -y git wget
WORKDIR /root/src
RUN wget https://dl.google.com/go/go1.24.5.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go1.24.5.linux-amd64.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"
RUN git clone https://gitlab.com/yawning/obfs4.git obfs4
WORKDIR /root/src/obfs4
RUN go build -o obfs4proxy/obfs4proxy ./obfs4proxy
RUN mkdir -p /opt/bin
RUN cp obfs4proxy/obfs4proxy /opt/bin/

FROM base AS build-arti
# Install Rust
RUN apt-get update && apt-get install -y \
    libssl-dev \
    libsqlite3-dev \
    pkg-config \
    curl
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
WORKDIR /root/src
RUN git clone https://gitlab.torproject.org/tpo/core/arti.git
WORKDIR /root/src/arti
# Build arti-extra
RUN cargo build --locked --verbose \
    --target x86_64-unknown-linux-gnu \
    -p arti -p tor-circmgr \
    --bin arti \
    --features full,restricted-discovery,arti-client/keymgr,onion-service-service,vanguards,ctor-keystore
RUN mv target/x86_64-unknown-linux-gnu/debug/arti target/x86_64-unknown-linux-gnu/debug/arti-extra
# Build vanilla arti
RUN cargo build --locked --verbose --target x86_64-unknown-linux-gnu -p arti
# Copy binaries to /opt
RUN mkdir -p /opt/bin
RUN cp target/x86_64-unknown-linux-gnu/debug/arti /opt/bin/
RUN cp target/x86_64-unknown-linux-gnu/debug/arti-extra /opt/bin/



FROM base AS simulate
WORKDIR /mnt
# # python deps for tornettools etc.
RUN apt-get update && apt-get install -y \
  dstat \
  procps \
  xz-utils \
  faketime
# tor runtime deps
RUN apt-get update && apt-get install -y \
  zlib1g-dev \
  libevent-dev \
  openssl \
  libssl-dev \
  libpsl-dev \
  libpsl5
# shadow runtime deps
RUN apt-get update && apt-get install -y \
  libglib2.0-0 \
  libigraph-dev \
  libprocps-dev

  
RUN echo fs.nr_open = 104857600 >> /etc/sysctl.conf
RUN echo fs.file-max = 104857600 >> /etc/sysctl.conf
RUN echo vm.max_map_count = 1073741824 >> /etc/sysctl.conf
RUN echo kernel.pid_max = 4194300 >> /etc/sysctl.conf
RUN echo kernel.threads-max = 4194300 >> /etc/sysctl.conf
#RUN sysctl -p
# Get the binaries for our sim tools

RUN mkdir -p /usr/bin
COPY --from=build-obfs4proxy /opt/bin/obfs4proxy /usr/bin/obfs4proxy


COPY --from=build-shadow /opt /opt/
COPY --from=build-tgen /opt /opt/
COPY --from=build-tor /opt /opt/
COPY --from=build-oniontrace /opt /opt/
COPY --from=build-tornettools /opt /opt/
COPY --from=build-arti /opt /opt/

COPY --from=build-arti /root/src/arti /opt/src/arti
# Setup run env
ENV PYVENV=/opt
ENV PATH=/opt/bin:$PATH
ENV LD_LIBRARY_PATH=/opt/lib

WORKDIR /mnt

# RUN wget https://collector.torproject.org/archive/relay-descriptors/consensuses/consensuses-2025-07.tar.xz
# RUN wget https://collector.torproject.org/archive/relay-descriptors/server-descriptors/server-descriptors-2025-07.tar.xz
# RUN wget https://metrics.torproject.org/userstats-relay-country.csv
# RUN wget https://collector.torproject.org/archive/onionperf/onionperf-2025-07.tar.xz
# RUN wget -O bandwidth-2025-07.csv "https://metrics.torproject.org/bandwidth.csv?start=2025-07-01&end=2025-07-31"
# RUN tar xaf consensuses-2025-07.tar.xz
# RUN tar xaf server-descriptors-2025-07.tar.xz
# RUN tar xaf onionperf-2025-07.tar.xz
# RUN git clone https://github.com/tmodel-ccs2018/tmodel-ccs2018.github.io.git


ENTRYPOINT ["bash"]