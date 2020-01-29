#!/bin/bash
#sudo docker run -d -t -e INTERFACE=wlp2s0 -v /var/run/docker.sock:/var/run/docker.sock --privileged iot_wireless
sudo docker run -d -t -e INTERFACE=wlp2s0 --net host --privileged iot_wireless

