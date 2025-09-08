Steps for Tor Docker container


## Create image
 `docker build -t tor-shadow-sim:latest . `

### If you are installing Shadow within a Docker container, you must increase the size of the container's /dev/shm mount and disable the seccomp security profile. You can do this by passing additional flags to docker run.

 `docker run -it --shm-size=1024g --security-opt seccomp=unconfined gabbyhalpin/tor-shadow-sim:latest`


### Generate the network. Once the Docker container is running, you can simulate the network with the modified tonettools config and tgen files. 
### *Note: simulating a '1%' Tor network for 60 simulation minutes can take as much as 30GiB of RAM. For more information visit the official tornettools repo: [tornettools](https://github.com/shadow/tornettools/tree/df6ada5e74c1eda22899610e4d1bed13a37878eb)

sudo apt-get install openssl libssl-dev libevent-dev build-essential automake zlib1g zlib1g-dev
git clone https://git.torproject.org/tor.git
cd tor
./autogen.sh
./configure --disable-asciidoc --disable-unittests --disable-manpage --disable-html-manual
make -j$(nproc)
cd ..

export PATH=${PATH}:`pwd`/tor/src/core/or:`pwd`/tor/src/app:`pwd`/tor/src/tools


Running Shadow

Tornettools:

tornettools stage \
    consensuses-2025-07 \
    server-descriptors-2025-07 \
    userstats-relay-country.csv \
    tmodel-ccs2018.github.io \
    --onionperf_data_path onionperf-2025-07 \
    --bandwidth_data_path bandwidth-2025-07.csv \
    --geoip_path tor/src/config/geoip


tornettools generate \
    relayinfo_staging_2025-07-01--2025-07-31.json \
    userinfo_staging_2025-07-01--2025-07-31.json \
    networkinfo_staging.gml \
    tmodel-ccs2018.github.io \
    --network_scale 0.01 \
    --prefix tornet-0.01_6


python3 setup_wf_network.py tornet-0.01_6 --verbose



fix start time 7200 (vim config file)

sed -i 's|~/.local/bin/tor|/opt/bin/tor|g' tornet-0.01_6/shadow.config.yaml
sed -i 's|~/.local/bin/oniontrace|/opt/bin/oniontrace|g' tornet-0.01_6/shadow.config.yaml
sed -i 's|~/.local/bin/tgen|/opt/bin/tgen|g' tornet-0.01_6/shadow.config.yaml

tornettools simulate tornet-0.01_6








