Steps for Tor Docker container


## Create image
 `docker build -t tor-shadow-sim:latest . `

### If you are installing Shadow within a Docker container, you must increase the size of the container's /dev/shm mount and disable the seccomp security profile. You can do this by passing additional flags to docker run.

 `docker run -it --shm-size=1024g --security-opt seccomp=unconfined tor-shadow-sim:latest`


## Once the Docker container is running, you must stage the network using tornettools
    tornettools stage \
        consensuses-2025-04 \
        server-descriptors-2025-04 \
        userstats-relay-country.csv \
        tmodel-ccs2018.github.io \
        --onionperf_data_path onionperf-2025-04 \
        --bandwidth_data_path bandwidth-2025-04.csv \
        --geoip_path tor/src/config/geoip

## Then you want to generate the configuration files used to simulate the network. This is where you can specify the scale of the network. 
## *Note: simulating a '1%' Tor network for 60 simulation minutes can take as much as 30GiB of RAM. For more information visit the official tornettools repo: [tornettools](https://github.com/shadow/tornettools/tree/df6ada5e74c1eda22899610e4d1bed13a37878eb)
    tornettools generate \
        relayinfo_staging_2025-04-01--2025-04-30.json \
        userinfo_staging_2025-04-01--2025-04-30.json \
        networkinfo_staging.gml \
        tmodel-ccs2018.github.io \
        --network_scale 0.05 \
        --prefix tornet-0.05





