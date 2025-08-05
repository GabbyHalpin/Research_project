Steps for Tor Docker container


## Create image
 `docker build -t tor-shadow-sim:latest . `

### If you are installing Shadow within a Docker container, you must increase the size of the container's /dev/shm mount and disable the seccomp security profile. You can do this by passing additional flags to docker run.

 `docker run -it --shm-size=1024g --security-opt seccomp=unconfined tor-shadow-sim:latest`


