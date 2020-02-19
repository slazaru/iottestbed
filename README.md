## Credit for previous work
This script was built using https://github.com/fgg89/docker-ap as a starting point

## Requirements
1. x86 linux machine with an ethernet and wireless interface
2. docker https://docs.docker.com/install/

## Features

### Pcap analysis 

### Network attack script

## Setup instructions

It is critically important to change the passwords in the wlan_config.txt file before running.

Run starttestbed.sh as sudo, specifying the wireless interface on your machine, eg:

`sudo ./starttestbed.sh start wlp5s0`

## Usage

Broadly speaking, there are two ways to use the testbed. You can run everything manually using ssh, or you can use the web interface.

### ssh

Get the address the container is running on by using docker inspect, eg:

`docker inspect iot_testbed`

Then ssh as root using port 54444, eg:

`ssh root@172.17.0.2 -p 54444`

### web interface

To enable the web command interface, local ssh port forwarding is required. Just add -L localhost:8000:localhost:8000 to the ssh command, eg:

`ssh -L localhost:8000:localhost:8000 root@172.17.0.2 -p 54444 `

Now you will be able to use the web interface on the home page


