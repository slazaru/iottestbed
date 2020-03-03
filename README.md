## Example Results

As of the time of writing, some example reports generated using this testbed can be viewed at http://www.cse.unsw.edu.au/~z3291606/ 

## Requirements
1. x86 64bit Linux machine with both an ethernet and wireless interface
2. Docker https://docs.docker.com/install/

## Setup instructions

It is critically important to change the passwords in the wlan_config.txt file before running.

Run starttestbed.sh as sudo, specifying the wireless interface on your machine, eg:

`sudo ./starttestbed.sh start wlp5s0`

Set up time varies according to the resources available, based on experience it should take around 30 minutes to set up on a 100 Mb connection with a dual core CPU, 8 gigs RAM and SSD.

If all went well, the iot_testbed Docker container should now be running, and a wireless network will now be available according to the configuration details in wlan_config.txt

## Usage

Broadly speaking, there are two ways to use the testbed. You can run everything manually using ssh, or you can use the web interface.

#### ssh

Get the address the container is running on by using docker inspect, eg:

`docker inspect iot_testbed`

Then ssh as root using port 54444, eg:

`ssh root@172.17.0.2 -p 54444`

#### Web Interface

To enable the web command interface, local ssh port forwarding is required. Just add -L localhost:8000:localhost:8000 to the ssh command, eg:

`ssh -L localhost:8000:localhost:8000 root@172.17.0.2 -p 54444 `

Now you will be able to use the web interface on the home page

## Example Workflow

While the testbed is running, all traffic on the network is saved in pcap files in the directory /captures

Say we have an IoT device that was we want to test for information leakage and vulnerabilities, call it the device under test (DUT)

#### Information leakage and pcap analysis

To test for information leakage, the testbed uses several open-source tools to analyze the pcap files containing the network traffic of the DUT

Suppose that you've connected the DUT to the testbed wireless network for 10 minutes and want to analyse the traffic from the last 10 minutes. To do this, you could run:

`pcapreporter 10m 10m`

The first argument is the time interval, the second argument is the name of the test

Alternatively, you can also specify an exact time interval, to see the details of this option use the help option

`pcapreporter -h`

Assuming all goes well, eventually reports will be generated and be viewable on the device home page. 

You can view the device home page by connecting to the iot testbed wireless network, opening a web browser and navigating to the ip address of the Docker container, which by default should be 192.168.4.1

#### Network-based vulnerability scanning

To test for network-based vulnerability, the testbed uses a custom Python script to carry out attacks against the DUT.

If it's the first time connecting the DUT to the network, you can use the monitor.py script. This script monitors the Zeek DHCP log for changes and prompts you with the MAC and IP address of the device when it connects. At this point you can also optionally run the attack script against the device.

To use the monitor script:

`monitor`

You can also run the attack script against the device directly, if you already know the IP address:

`attack <ipv4 address>`

Assuming all goes well, eventually reports will be generated and be viewable on the device home page.

You can view the device home page by connecting to the iot testbed wireless network, opening a web browser and then navigating to the ip address of the Docker container, which by default should be 192.168.4.1

## Credit for previous work
This script was built using https://github.com/fgg89/docker-ap as a starting point

