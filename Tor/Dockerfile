FROM ubuntu:22.04 AS base
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ENV DEBIAN_FRONTEND=noninteractive

# Define software versions
# ENV ONIONTRACE_COMMIT=f271ead90526b29b3dd7218ce6e56813e3b4dce3
# ENV TORNETTOOLS_COMMIT=75e59fab4f4e95fc7636df44202e287d76bfefea
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


# build special wget2 that supports socks proxy
# FROM base as build-wget2
# COPY wget2-socks.tar /root/src/wget2-socks.tar
# WORKDIR /root/src
# RUN tar xaf wget2-socks.tar
# WORKDIR /root/src/wget2-socks
# RUN apt-get update && apt-get install -y \
#   autoconf \
#   automake \
#   autogen \
#   autopoint \
#   libtool \
#   gettext \
#   gcc \
#   make \
#   rsync \
#   wget \
#   tar \
#   texinfo \
#   pkg-config \
#   flex \
#   lzip \
#   gnupg1 \
#   libfl-dev \
#   libidn2-dev \
#   libpsl-dev \
#   libgnutls28-dev \
#   libiconv-hook-dev \
#   zlib1g-dev \
#   libpcre2-dev \
#   libgpgme-dev \
#   libassuan-dev \
#   libnghttp2-dev
# RUN git config --global --add safe.directory /root/src/wget2-socks
# RUN git config --global --add safe.directory /root/src/wget2-socks/gnulib
# RUN ./bootstrap
# RUN ./configure \
#   --prefix=/opt \
#   --enable-threads=posix \
#   --disable-doc \
#   --without-lzip \
#   --without-libhsts
# # ENV CPPFLAGS=-DDEBUG
# # ENV CFLAGS="-ggdb -O0"
# RUN make
# RUN make install

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
# wget2 runtime deps
# RUN apt-get update && apt-get install -y \
#   gnupg1 \
#   libfl-dev \
#   libidn2-dev \
#   libpsl-dev \
#   libgnutls28-dev \
#   libiconv-hook-dev \
#   zlib1g-dev \
#   libpcre2-dev \
#   libgpgme-dev \
#   libassuan-dev \
#   libnghttp2-dev
# perf
#RUN apt-get update && apt-get install -y linux-tools-generic
#RUN mkdir -p /root/.local/bin
#RUN ln -s /usr/lib/linux-tools/5.4.0-81-generic/perf /root/.local/bin/perf
#COPY --from=tornettools-generate /root/data/tornet-* /root/data/tornet
RUN echo fs.nr_open = 104857600 >> /etc/sysctl.conf
RUN echo fs.file-max = 104857600 >> /etc/sysctl.conf
RUN echo vm.max_map_count = 1073741824 >> /etc/sysctl.conf
RUN echo kernel.pid_max = 4194300 >> /etc/sysctl.conf
RUN echo kernel.threads-max = 4194300 >> /etc/sysctl.conf
#RUN sysctl -p
# Get the binaries for our sim tools
COPY --from=build-shadow /opt /opt/
COPY --from=build-tgen /opt /opt/
COPY --from=build-tor /opt /opt/
COPY --from=build-oniontrace /opt /opt/
COPY --from=build-tornettools /opt /opt/
# COPY --from=build-wget2 /opt /opt/
# Setup run env
ENV PYVENV=/opt
ENV PATH=/opt/bin:$PATH
ENV LD_LIBRARY_PATH=/opt/lib

WORKDIR /mnt

RUN wget https://collector.torproject.org/archive/relay-descriptors/consensuses/consensuses-2025-07.tar.xz
RUN wget https://collector.torproject.org/archive/relay-descriptors/server-descriptors/server-descriptors-2025-07.tar.xz
RUN wget https://metrics.torproject.org/userstats-relay-country.csv
RUN wget https://collector.torproject.org/archive/onionperf/onionperf-2025-07.tar.xz
RUN wget -O bandwidth-2025-07.csv "https://metrics.torproject.org/bandwidth.csv?start=2025-07-01&end=2025-07-31"
RUN tar xaf consensuses-2025-07.tar.xz
RUN tar xaf server-descriptors-2025-07.tar.xz
RUN tar xaf onionperf-2025-07.tar.xz
RUN git clone https://github.com/tmodel-ccs2018/tmodel-ccs2018.github.io.git

# RUN git clone https://git.torproject.org/tor.git
# RUN cd tor
# RUN ./autogen.sh
# RUN ./configure --disable-asciidoc --disable-unittests --disable-manpage --disable-html-manual
# RUN make -j$(nproc)
# RUN cd ..
# RUN export PATH=${PATH}:`pwd`/tor/src/core/or:`pwd`/tor/src/app:`pwd`/tor/src/tools

ENTRYPOINT ["bash"]