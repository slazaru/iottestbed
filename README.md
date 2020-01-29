## Credit for previous work
This script was built using https://github.com/fgg89/docker-ap as a starting point

## Requirements
1. x86 linux machine with an ethernet and wireless interface
2. docker https://docs.docker.com/install/

## Setup instructions

It is critically important to change the passwords in the wlan_config.txt file before running

Run starttestbed.sh as sudo, specifying the wireless interface on your machine, eg:

`sudo ./starttestbed.sh start wlp5s0`

## Usage

### ssh

Get the address the container is running on by using docker inspect, eg:

`docker inspect iot_testbed`

Then ssh as root using port 54444, eg:

`ssh root@172.17.0.2 -p 54444`
