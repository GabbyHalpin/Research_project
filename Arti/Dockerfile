# 1) Base image
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# 2) Install all system-level dependencies as root
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
     libc-dbg \
     libigraph-dev \
     libsqlite3-dev \
     make \
     netbase \
     xz-utils \
     util-linux \
     gcc \
     g++ \
     autoconf \
     automake \
     libtool \
     openssl \
     libssl-dev \
     zlib1g-dev \
     ca-certificates \
     faketime \
     dstat \
     procps \
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
RUN git clone https://github.com/shadow/shadow.git shadow-src \
 && cd shadow-src \
 && ./setup build --clean --test --prefix=${HOME}/.local \
 && ./setup install \
 && cd .. \
 && rm -rf shadow-src

# 8) Build & install TGen into ~/.local
RUN git clone https://github.com/shadow/tgen.git tgen-src \
 && mkdir -p tgen-src/build \
 && cd tgen-src/build \
 && cmake .. -DCMAKE_INSTALL_PREFIX=${HOME}/.local \
 && make install \
 && cd ../.. \
 && rm -rf tgen-src

# 9) Build & install OnionTrace into ~/.local
RUN git clone https://github.com/shadow/oniontrace.git oniontrace-src \
 && mkdir -p oniontrace-src/build \
 && cd oniontrace-src/build \
 && cmake .. -DCMAKE_INSTALL_PREFIX=${HOME}/.local \
 && make install \
 && cd ../.. \
 && rm -rf oniontrace-src

# 10) Install tornettools into ~/.local
RUN git clone https://github.com/shadow/tornettools.git tornettools-src \
 && cd tornettools-src \
 && python3 -m pip install --user -r requirements.txt \
 && python3 -m pip install --user . \
 && cd .. \
 && rm -rf tornettools-src

# 11) (Optionally) Fetch Tor network data under $HOME
# fetch data for the tornettools network 
RUN wget https://collector.torproject.org/archive/relay-descriptors/consensuses/consensuses-2025-04.tar.xz &&\
    wget https://collector.torproject.org/archive/relay-descriptors/server-descriptors/server-descriptors-2025-04.tar.xz &&\ 
    wget https://metrics.torproject.org/userstats-relay-country.csv &&\ 
    wget https://collector.torproject.org/archive/onionperf/onionperf-2025-04.tar.xz &&\ 
    wget -O bandwidth-2025-04.csv "https://metrics.torproject.org/bandwidth.csv?start=2025-04-01&end=2025-04-30" &&\ 
    tar xaf consensuses-2025-04.tar.xz &&\ 
    tar xaf server-descriptors-2025-04.tar.xz &&\ 
    tar xaf onionperf-2025-04.tar.xz

# 12) Clone t-model repo
RUN git clone https://github.com/tmodel-ccs2018/tmodel-ccs2018.github.io.git

# 13) Build & install Tor from source into ~/.local
RUN git clone https://git.torproject.org/tor.git tor-src \
 && cd tor-src \
 && ./autogen.sh \
 && ./configure \
      --prefix=${HOME}/.local \
      --disable-asciidoc \
      --disable-unittests \
      --disable-manpage \
      --disable-html-manual \
 && make -j"$(nproc)" \
 && make install \
 && cd .. \
 && rm -rf tor-src

# 14) Build obfs4proxy into ~/.local/bin
RUN wget https://dl.google.com/go/go1.24.5.linux-amd64.tar.gz \
 && tar -C ${HOME} -xzf go1.24.5.linux-amd64.tar.gz \
 && git clone https://gitlab.com/yawning/obfs4.git obfs4-src \
 && cd obfs4-src \
 && ${HOME}/go/bin/go build -o obfs4proxy/obfs4proxy ./obfs4proxy \
 && mkdir -p ${HOME}/.local/bin \
 && cp obfs4proxy/obfs4proxy ${HOME}/.local/bin/ \
 && cd .. \
 && rm -rf obfs4-src go1.24.5.linux-amd64.tar.gz

# 15) Upgrade networkx in user‐space
RUN python3 -m pip install --user --upgrade networkx

# 16) Build & install Arti (and arti-extra) into ~/.local/bin
RUN git clone https://gitlab.torproject.org/tpo/core/arti.git arti-src \
 && cd arti-src \
   # debug build for Shadow
 && cargo build --locked --verbose \
      --target x86_64-unknown-linux-gnu \
      -p arti -p tor-circmgr \
      --bin arti \
      --features full,restricted-discovery,arti-client/keymgr,onion-service-service,vanguards,ctor-keystore \
 && mkdir -p ${HOME}/.local/bin \
 && cp target/x86_64-unknown-linux-gnu/debug/arti target/x86_64-unknown-linux-gnu/debug/arti-extra \
 && cp target/x86_64-unknown-linux-gnu/debug/arti-extra ${HOME}/.local/bin/ \
   # vanilla debug build
 && cargo build --locked --verbose --target x86_64-unknown-linux-gnu -p arti \
 && cp target/x86_64-unknown-linux-gnu/debug/arti ${HOME}/.local/bin/arti \
   # release build
 && cargo build -p arti --release \
 && cp target/release/arti ${HOME}/.local/bin/arti-release \
 && cd .. \
 # && rm -rf arti-src
# # 17) Copy your simulation files & generate host keys
# COPY --chown=${USER}:${USER} shadow_expanded.yaml \
#                            tgen.client.graphml.xml \
#                            tgen.torclient.graphml.xml \
#                            tgen.server.graphml.xml  ./

WORKDIR /home/${USER}/arti/tests/shadow/shadow.data.template/hosts
COPY --chown=${USER}:${USER} generate_arti.py .
RUN ls -la ../../

ENV PATH=${HOME}/.local/bin:$PATH
RUN python3 -m pip install --user pynacl \
 && python3 generate_arti.py

# 18) Drop into bash in your user’s home
WORKDIR /home/${USER}
ENTRYPOINT ["bash"]
