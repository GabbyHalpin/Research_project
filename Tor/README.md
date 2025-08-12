Steps for Tor Docker container


## Create image
 `docker build -t tor-shadow-sim:latest . `

### If you are installing Shadow within a Docker container, you must increase the size of the container's /dev/shm mount and disable the seccomp security profile. You can do this by passing additional flags to docker run.

 `docker run -it --shm-size=1024g --security-opt seccomp=unconfined gabbyhalpin/tor-shadow-sim:latest`


### Convert the shadow.config.yaml file
`python3 convert_config.py tornet-0.05 urls.txt -v`


### Once the Docker container is running, you can simulate the network with the modified tonettools config and tgen files. 
### *Note: simulating a '1%' Tor network for 60 simulation minutes can take as much as 30GiB of RAM. For more information visit the official tornettools repo: [tornettools](https://github.com/shadow/tornettools/tree/df6ada5e74c1eda22899610e4d1bed13a37878eb)
tornettools simulate tornet-0.05
tornettools parse tornet-0.05
tornettools plot \
    tornet-0.05 \
    --tor_metrics_path tor_metrics_2025-04-01--2025-04-30.json \
    --prefix pdfs
tornettools archive tornet-0.05








