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
     python3-lxml \
     python3-numpy \
     python3-scipy \
     python3-pandas \
     python3-yaml \
     python3-requests \
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
     tcpdump \
     tshark \
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

# Install additional Python packages for WF research
RUN python3 -m pip install --user \
    scapy \
    stem \
    matplotlib \
    seaborn \
    scikit-learn \
    torch \
    tensorflow \
    jupyter

# 6) Install Rust toolchain into ~/.cargo
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y

# Ensure cargo is in PATH for non-login shells
SHELL ["/bin/bash", "-lc"]

# 7) Build & install Shadow into ~/.local
RUN git clone https://github.com/shadow/shadow.git shadow \
 && cd shadow \
 && ./setup build --clean --test --prefix=${HOME}/.local \
 && ./setup install

# 8) Build & install TGen into ~/.local
RUN git clone https://github.com/shadow/tgen.git tgen \
 && mkdir -p tgen/build \
 && cd tgen/build \
 && cmake .. -DCMAKE_INSTALL_PREFIX=${HOME}/.local \
 && make install 

# 9) Build & install OnionTrace into ~/.local
RUN git clone https://github.com/shadow/oniontrace.git oniontrace \
 && mkdir -p oniontrace/build \
 && cd oniontrace/build \
 && cmake .. -DCMAKE_INSTALL_PREFIX=${HOME}/.local \
 && make install

# 10) Install tornettools into ~/.local
RUN git clone https://github.com/shadow/tornettools.git tornettools \
 && cd tornettools \
 && python3 -m pip install --user -r requirements.txt \
 && python3 -m pip install --user . 

# 11) Fetch Tor network data under $HOME
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
RUN git clone https://git.torproject.org/tor.git tor \
 && cd tor \
 && ./autogen.sh \
 && ./configure \
      --prefix=${HOME}/.local \
      --disable-asciidoc \
      --disable-unittests \
      --disable-manpage \
      --disable-html-manual \
 && make -j"$(nproc)" \
 && make install

# 14) Build obfs4proxy into ~/.local/bin
RUN wget https://dl.google.com/go/go1.24.5.linux-amd64.tar.gz \
 && tar -C ${HOME} -xzf go1.24.5.linux-amd64.tar.gz \
 && git clone https://gitlab.com/yawning/obfs4.git obfs4 \
 && cd obfs4 \
 && ${HOME}/go/bin/go build -o obfs4proxy/obfs4proxy ./obfs4proxy \
 && mkdir -p ${HOME}/.local/bin \
 && cp obfs4proxy/obfs4proxy ${HOME}/.local/bin/

# 15) Upgrade networkx in user‐space
RUN python3 -m pip install --user --upgrade networkx

# 16) Stage the network using imported data
RUN tornettools stage \
    consensuses-2025-04 \
    server-descriptors-2025-04 \
    userstats-relay-country.csv \
    tmodel-ccs2018.github.io \
    --onionperf_data_path onionperf-2025-04 \
    --bandwidth_data_path bandwidth-2025-04.csv \
    --geoip_path tor/src/config/geoip

# 17) Generate base network at 5% scale
RUN tornettools generate \
    relayinfo_staging_2025-04-01--2025-04-30.json \
    userinfo_staging_2025-04-01--2025-04-30.json \
    networkinfo_staging.gml \
    tmodel-ccs2018.github.io \
    --network_scale 0.05 \
    --prefix tornet-0.05

# # 18) Generate network variations for robustness testing (following simulation paper)
# RUN for seed in 1 2 3; do \
#         for load in 1.5 2.0 2.5; do \
#             echo "Generating network variant: seed=${seed}, load=${load}"; \
#             tornettools generate \
#                 relayinfo_staging_2025-04-01--2025-04-30.json \
#                 userinfo_staging_2025-04-01--2025-04-30.json \
#                 networkinfo_staging.gml \
#                 tmodel-ccs2018.github.io \
#                 --network_scale 0.05 \
#                 --load_scale ${load} \
#                 --seed ${seed} \
#                 --prefix tornet-0.05-seed${seed}-load${load}; \
#         done; \
#     done

# 19) Copy user scripts and data
COPY --chown=${USER}:${USER} urls.txt .
COPY --chown=${USER}:${USER} convert_config.py .
COPY --chown=${USER}:${USER} data_processor.py .
COPY --chown=${USER}:${USER} process_wf_data.sh .
COPY --chown=${USER}:${USER} run_simulation.sh .
#COPY --chown=${USER}:${USER} run_all_simulations.sh .

# # 20) Run configuration conversion for all generated networks
# RUN echo "Converting base network configuration..." && \
#     python3 convert_config.py tornet-0.05 urls.txt -v

# # Convert all network variations
# RUN for seed in 1 2 3; do \
#         for load in 1.5 2.0 2.5; do \
#             network_dir="tornet-0.05-seed${seed}-load${load}"; \
#             echo "Converting network variant: ${network_dir}"; \
#             python3 convert_config.py ${network_dir} urls.txt; \
#         done; \
#     done

# RUN echo "=== WEBSITE FINGERPRINTING RESEARCH SETUP COMPLETE ===" && \
#     echo "Generated networks:" && \
#     ls -d tornet-* && \
#     echo "" && \
#     echo "✅ All configurations modified for WF research" && \
#     echo "✅ URLs processed and integrated" && \
#     echo "✅ Helper scripts created" && \
#     echo "" && \
#     echo "Read WF_RESEARCH_SETUP.md for next steps" && \
#     echo "Ready for simulation and data collection!"

WORKDIR /home/${USER}
ENTRYPOINT ["bash"]