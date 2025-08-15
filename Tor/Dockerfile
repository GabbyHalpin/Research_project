# 1) Base image
FROM ubuntu:22.04 AS base

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y apt-utils git sudo
RUN apt-get install -y locales

# 2) Install all system-level dependencies AS root
RUN apt-get update \
 && apt-get install -y \
     vim \
     build-essential \
     cmake \
     git \
     wget \
     curl \
     python3 \
     python3-pip \
     python3-networkx \
     libglib2.0-0 \
     libglib2.0-dev \
     libevent-dev \
     libclang-dev \
     libpsl5 \
     libpsl-dev \
     libc-dbg \
     libigraph-dev \
     libsqlite3-dev \
     locales \
     tzdata \
     make \
     netbase \
     xz-utils \
     util-linux \
     gcc \
     g++ \
     autoconf \
     automake \
     autopoint \
     autogen \
     libtool \
     gettext \
     rsync \
     openssl \
     libssl-dev \
     zlib1g-dev \
     ca-certificates \
     faketime \
     dstat \
     procps \
     texinfo \
     pkg-config \
     flex \
     lzip \
     gnupg1 \
     libfl-dev \
     libidn2-dev \
     libpsl-dev \
     libgnutls28-dev \
     libiconv-hook-dev \
     zlib1g-dev \
     libpcre2-dev \
     libgpgme-dev \
     libassuan-dev \
     libnghttp2-dev \
 && rm -rf /var/lib/apt/lists/*

# 3) Create a non-root user and home dir
ARG USER=artiuser
ARG UID=1000
RUN useradd --uid ${UID} --create-home --shell /bin/bash ${USER}

# 4) Switch to non-root user
USER ${USER}
WORKDIR /home/${USER}
ENV HOME=/home/${USER}
ENV PATH=${HOME}/.local/bin:${HOME}/.cargo/bin:/usr/local/bin:${PATH}

# 5) Upgrade pip and install Python packages into ~/.local
RUN python3 -m pip install --upgrade pip --user

# 6) Install Rust toolchain into ~/.cargo
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y

# Ensure cargo is in PATH for non-login shells
SHELL ["/bin/bash", "-lc"]

# 7) Build & install Shadow into ~/.local
FROM base AS build-shadow
USER ${USER}
WORKDIR /home/${USER}
RUN git clone https://github.com/shadow/shadow.git
WORKDIR /home/${USER}/shadow
# Switch to root temporarily for install_deps
RUN ./setup build --jobs `nproc` --prefix=${HOME}/.local --clean
RUN ./setup install

# 8) Build & install TGen into ~/.local
FROM base AS build-tgen
USER ${USER}
WORKDIR /home/${USER}
RUN git clone https://github.com/shadow/tgen.git tgen \
 && mkdir -p tgen/build \
 && cd tgen/build \
 && cmake .. -DCMAKE_INSTALL_PREFIX=${HOME}/.local \
 && make install 
WORKDIR /home/${USER}/tgen/tools
RUN pip3 install --user -r requirements.txt
RUN pip3 install --user -I .

# 9) Build & install OnionTrace into ~/.local
FROM base AS build-oniontrace
USER ${USER}
WORKDIR /home/${USER}
RUN git clone https://github.com/shadow/oniontrace.git oniontrace \
 && mkdir -p oniontrace/build \
 && cd oniontrace/build \
 && cmake .. -DCMAKE_INSTALL_PREFIX=${HOME}/.local \
 && make install
WORKDIR /home/${USER}/oniontrace/tools
RUN pip3 install --user -r requirements.txt
RUN pip3 install --user -I .

# 10) Build & install Tor from source into ~/.local
FROM base AS build-tor
USER ${USER}
WORKDIR /home/${USER}
RUN git clone https://git.torproject.org/tor.git tor
WORKDIR /home/${USER}/tor
RUN ./autogen.sh 
ENV LIBS=-lpsl
RUN ./configure \
      --prefix=${HOME}/.local \
      --disable-asciidoc \
      --disable-unittests \
      --disable-manpage \
      --disable-html-manual \
 && make -j"$(nproc)" \
 && make install

# 11) Install tornettools into ~/.local
FROM base AS build-tornettools
USER ${USER}
WORKDIR /home/${USER}
RUN git clone https://github.com/shadow/tornettools.git tornettools \
 && cd tornettools \
 && python3 -m pip install --user -r requirements.txt \
 && python3 -m pip install --user . 


# 12) build special wget2 that supports socks proxy
FROM base AS build-wget2
USER ${USER}
WORKDIR /home/${USER}

# Clone wget2 directly
RUN git clone https://gitlab.com/gnuwget/wget2.git
WORKDIR /home/${USER}/wget2
RUN git checkout edfd08

RUN git clone https://github.com/coreutils/gnulib.git gnulib
RUN git submodule init && git submodule update

# Copy and apply patch
COPY --chown=${USER}:${USER} wget2/socks.patch ./
RUN git config --global user.email "builder@example.com" && \
    git config --global user.name "Docker Builder"
RUN git am socks.patch 

# Configure git safely
RUN git config --global --add safe.directory /home/${USER}/wget2

# Build and install
RUN ./bootstrap
RUN ./configure --prefix=${HOME}/.local --enable-threads=posix --disable-doc --without-lzip --without-libhsts
RUN make -j"$(nproc)"
RUN make install


# Build obfs4proxy into ~/.local/bin
FROM base AS build-obfs4proxy
RUN wget https://dl.google.com/go/go1.24.5.linux-amd64.tar.gz \
 && tar -C ${HOME} -xzf go1.24.5.linux-amd64.tar.gz \
 && git clone https://gitlab.com/yawning/obfs4.git obfs4 \
 && cd obfs4 \
 && ${HOME}/go/bin/go build -o obfs4proxy/obfs4proxy ./obfs4proxy \
 && mkdir -p ${HOME}/.local/bin \
 && cp obfs4proxy/obfs4proxy ${HOME}/.local/bin/

# 13) FINAL STAGE - Combine all built tools
FROM base AS final
USER ${USER}
WORKDIR /home/${USER}

# Copy built binaries and libraries from all build stages
COPY --from=build-shadow --chown=${USER}:${USER} /home/${USER}/.local /home/${USER}/.local
COPY --from=build-tgen --chown=${USER}:${USER} /home/${USER}/.local /home/${USER}/.local
COPY --from=build-oniontrace --chown=${USER}:${USER} /home/${USER}/.local /home/${USER}/.local
COPY --from=build-tor --chown=${USER}:${USER} /home/${USER}/.local /home/${USER}/.local
COPY --from=build-tornettools --chown=${USER}:${USER} /home/${USER}/.local /home/${USER}/.local
COPY --from=build-wget2 --chown=${USER}:${USER} /home/${USER}/.local /home/${USER}/.local
COPY --from=build-obfs4proxy --chown=${USER}:${USER} /home/${USER}/.local /home/${USER}/.local

# Copy the Tor source directory for geoip files
COPY --from=build-tor --chown=${USER}:${USER} /home/${USER}/tor /home/${USER}/tor

# Copy Python packages from tornettools and tgen builds
COPY --from=build-tornettools --chown=${USER}:${USER} /home/${USER}/.local/lib/python3.10/site-packages /home/${USER}/.local/lib/python3.10/site-packages
COPY --from=build-tgen --chown=${USER}:${USER} /home/${USER}/.local/lib/python3.10/site-packages /home/${USER}/.local/lib/python3.10/site-packages
COPY --from=build-oniontrace --chown=${USER}:${USER} /home/${USER}/.local/lib/python3.10/site-packages /home/${USER}/.local/lib/python3.10/site-packages

# Install additional Python packages
RUN pip3 install --user zimply
RUN export PATH=${PATH}:`pwd`/tor/src/core/or:`pwd`/tor/src/app:`pwd`/tor/src/tools

# (Optionally) Fetch Tor network data under $HOME
RUN wget https://collector.torproject.org/archive/relay-descriptors/consensuses/consensuses-2025-07.tar.xz &&\
    wget https://collector.torproject.org/archive/relay-descriptors/server-descriptors/server-descriptors-2025-07.tar.xz &&\ 
    wget https://metrics.torproject.org/userstats-relay-country.csv &&\ 
    wget https://collector.torproject.org/archive/onionperf/onionperf-2025-07.tar.xz &&\ 
    wget -O bandwidth-2025-07.csv "https://metrics.torproject.org/bandwidth.csv?start=2025-07-01&end=2025-07-31" &&\ 
    tar xaf consensuses-2025-07.tar.xz &&\ 
    tar xaf server-descriptors-2025-07.tar.xz &&\ 
    tar xaf onionperf-2025-07.tar.xz

# Clone t-model repo
RUN git clone https://github.com/tmodel-ccs2018/tmodel-ccs2018.github.io.git

# Upgrade networkx in user‐space
RUN python3 -m pip install --user --upgrade networkx

# Copy application files
COPY --chown=${USER}:${USER} urls.txt .
COPY --chown=${USER}:${USER} generate_websites.py .
COPY --chown=${USER}:${USER} run_wf_simulation.sh .
COPY --chown=${USER}:${USER} setup_wf_network.py .
COPY --chown=${USER}:${USER} wf_classifiers.py .


# Verify installations work
RUN which shadow || echo "Shadow not found"
RUN which tor || echo "Tor not found"
RUN which tgen || echo "TGen not found" 
RUN which oniontrace || echo "OnionTrace not found"
RUN python3 -c "import tornettools; print('tornettools imported successfully')" || echo "tornettools import failed"

#Download wikidata
RUN mkdir -p wikidata && \
    cd wikidata && \
    wget -O wikipedia_en_top.zim \
    "https://download.kiwix.org/zim/wikipedia/wikipedia_en_100_maxi_2025-07.zim"

RUN tornettools stage \
    consensuses-2025-07 \
    server-descriptors-2025-07 \
    userstats-relay-country.csv \
    tmodel-ccs2018.github.io \
    --onionperf_data_path onionperf-2025-07 \
    --bandwidth_data_path bandwidth-2025-07.csv \
    --geoip_path tor/src/config/geoip

WORKDIR /home/${USER}
ENTRYPOINT ["bash"]