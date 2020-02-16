#!/bin/bash

#title           :starttestbed.sh
#description     :This script will start the testbed router
#author          :Fran Gonzalez mods ross lazarus sam lazarus
#usage           :bash starttestbed <start|stop> [interface]
#dependencies	 :docker, iw, pgrep, grep, iptables, cat, ip,
#                 bridge-utils, rfkill

MAGENTA='\e[0;35m'
RED='\e[0;31m'
GREEN='\e[0;32m'
BLUE='\e[0;34m'
NC='\e[0m'
ROOT_UID="0"
ARCH="$HOSTTYPE"

# WLAN parameters
SSID="testbed_ap"
HW_MODE="g"
CHANNEL="6"
PASSPHRASE="CHANGEMEPLS"
WPA_MODE="WPA-PSK"

# Other parameters
SUBNET="192.168.4"
IP_AP="192.168.4.1"
NETMASK="/24"
DNS_SERVER="8.8.8.8"
DOCKER_NAME="iot_testbed"
CONF_FILE="wlan_config.txt"
pushd "$(dirname "$0")" > /dev/null
PATHSCRIPT=$(pwd)
popd > /dev/null

if [ "$ARCH" == "x86_64" ]
then
    DOCKER_IMAGE="iot_testbed"
else
    echo "Currently supported architectures are x86_64 and armv7. Exiting..."
    exit 1
fi

show_usage () {
    echo -e "Usage: $0 <start|stop> [interface]"
    exit 1
}

if [ "$1" == "help" ] || [ "$#" -eq 0 ]
then
    show_usage
fi

# Check run as root
if [ "$UID" -ne "$ROOT_UID" ] ; then
    echo "You must be root to run this script!"
    exit 1
fi

# Argument check
if [ "$#" -eq 0 ] || [ "$#" -gt 2 ] 
then
    show_usage
fi

print_banner () {
	echo ""
    	echo -e "${MAGENTA}  IOT testbed    ${NC}"
	echo ""
}

init () {
    IFACE="$1"
    # zeek needs this later
    echo $IFACE > "$PATHSCRIPT"/device
    # Check that the requested iface is available
    if ! [ -e /sys/class/net/"$IFACE" ]
    then
        echo -e "${RED}[ERROR]${NC} The interface provided does not exist. Exiting..."
        exit 1
    fi
   
    # Check that the given interface is not used by the host as the default route
    if [[ $(ip r | grep default | cut -d " " -f5) == "$IFACE" ]]
    then
        echo -e "${BLUE}[INFO]${NC} The selected interface is configured as the default route, if you use it you will lose internet connectivity"
        while true;
        do
            read -p "Do you wish to continue? [y/n]" yn
            case $yn in
                [Yy]* ) break;;
                [Nn]* ) exit;;
                * ) echo "Please answer yes or no.";;
            esac
        done
	fi

    # Find the physical interface for the given wireless interface
    PHY=$(cat /sys/class/net/"$IFACE"/phy80211/name)

    # Architecture
    echo -e "${BLUE}[INFO]${NC} Architecture: ${GREEN}$ARCH${NC}"
    
    # Number of phy interfaces
    NUM_PHYS=$(iw dev | grep -c phy)
    echo -e "${BLUE}[INFO]${NC} Number of physical wireless interfaces connected: ${GREEN}$NUM_PHYS${NC}"
    
    # Checking if the docker image has been already pulled
    IMG_CHECK=$(docker images -q $DOCKER_IMAGE)
    if [ "$IMG_CHECK" != "" ]
    then
        echo -e "${BLUE}[INFO]${NC} Docker image ${GREEN}$DOCKER_IMAGE${NC} found"
    else
        echo -e "${BLUE}[INFO]${NC} Docker image ${RED}$DOCKER_IMAGE${NC} not found"
        # Option 1: Building
        echo -e "[+] Building the image ${GREEN}$DOCKER_IMAGE${NC} (Grab a coffee...)"
        if [ "$ARCH" == "x86_64" ]
        then
            docker build --rm -t $DOCKER_IMAGE -f "$PATHSCRIPT"/Dockerfile .
        fi
    fi

    ### Check if hostapd is running in the host
    hostapd_pid=$(pgrep hostapd)
    if [ ! "$hostapd_pid" == "" ] 
    then
       echo -e "${BLUE}[INFO]${NC} hostapd service is already running in the system, make sure you use a different wireless interface..."
       #kill -9 "$hostapd_pid"
    fi

    # Unblock wifi and bring the wireless interface up
    echo -e "${BLUE}[INFO]${NC} Unblocking wifi and setting ${IFACE} up"
    rfkill unblock wifi
    ip link set "$IFACE" up

    # Check if a wlan config file exists, else take wlan parameters by default
    if [ -e "$PATHSCRIPT"/"$CONF_FILE" ]
    then
        echo -e "${BLUE}[INFO]${NC} Found WLAN config file"
	    # Parse the wlan config file
		IFS="="
		while read -r name value
		do
                    case $name in
                        ''|\#* ) continue;; # Skip blank lines and lines starting with #
                        "SSID" )
                            SSID=${value//\"/}
                            echo -e "${BLUE}"[INFO]"${NC}" SSID: "${MAGENTA}""$SSID""${NC}";;
                        "PASSPHRASE" )
                            PASSPHRASE=${value//\"/};;
                        "HW_MODE" )
                            HW_MODE=${value//\"/};;
                        "CHANNEL" )
                            CHANNEL=${value//\"/};;
                        * )
                            #echo Parameter in "$PATHSCRIPT"/"$CONF_FILE" not recognized
		    esac
		done < "$PATHSCRIPT"/"$CONF_FILE"
    else
        echo -e "${BLUE}[INFO]${NC} WLAN config file not found. Setting default WLAN parameters"
        echo -e "${BLUE}"[INFO]"${NC}" SSID: "${MAGENTA}""$SSID""${NC}"
    fi

    ### Generating hostapd.conf file
    echo -e "[+] Generating hostapd.conf"
    sed -e "s/_SSID/$SSID/g" -e "s/_IFACE/$IFACE/" -e "s/_HW_MODE/$HW_MODE/g" -e "s/_CHANNEL/$CHANNEL/g" -e "s/_PASSPHRASE/$PASSPHRASE/g" -e "s/_WPA_MODE/$WPA_MODE/g" "$PATHSCRIPT"/templates/hostapd.template > "$PATHSCRIPT"/hostapd.conf

    ### Generating dnsmasq.conf file
    echo -e "[+] Generating dnsmasq.conf" 
    sed -e "s/_DNS_SERVER/$DNS_SERVER/g" -e "s/_IFACE/$IFACE/" -e "s/_SUBNET_FIRST/$SUBNET.20/g" -e "s/_SUBNET_END/$SUBNET.254/g" "$PATHSCRIPT"/templates/dnsmasq.template > "$PATHSCRIPT"/dnsmasq.conf
}

service_start () { 
    IFACE="$1"
    echo -e "[+] Starting the docker container with name ${GREEN}$DOCKER_NAME${NC}"
    docker run -dt --name $DOCKER_NAME --net=bridge -p 54444:54444 -e TZ=`cat /etc/timezone` --cap-add=NET_ADMIN --cap-add=NET_RAW -v "$PATHSCRIPT"/testbed/reports:/var/www/html -v "$PATHSCRIPT"/testbed/captures:/captures -v "$PATHSCRIPT"/testbed/uploads:/uploads -v "$PATHSCRIPT"/hostapd.conf:/etc/hostapd/hostapd.conf -v "$PATHSCRIPT"/dnsmasq.conf:/etc/dnsmasq.conf $DOCKER_IMAGE > /dev/null 2>&1
    pid=$(docker inspect -f '{{.State.Pid}}' $DOCKER_NAME)
    # Assign phy wireless interface to the container 
    mkdir -p /var/run/netns
    ln -s /proc/"$pid"/ns/net /var/run/netns/"$pid"
    iw phy "$PHY" set netns "$pid"
    
    ### Assign an IP to the wifi interface
    echo -e "[+] Configuring ${GREEN}$IFACE${NC} with IP address ${GREEN}$IP_AP${NC}"
    ip netns exec "$pid" ip addr flush dev "$IFACE"
    ip netns exec "$pid" ip link set "$IFACE" up
    ip netns exec "$pid" ip addr add "$IP_AP$NETMASK" dev "$IFACE"

    ### iptables rules for NAT
    echo "[+] Adding natting rule to iptables (container)"
    ip netns exec "$pid" iptables -t nat -A POSTROUTING -s $SUBNET.0$NETMASK ! -d $SUBNET.0$NETMASK -j MASQUERADE
    
    ### Enable IP forwarding
    echo "[+] Enabling IP forwarding (container)"
    ip netns exec "$pid" echo 1 > /proc/sys/net/ipv4/ip_forward
    ### start hostapd and dnsmasq in the container
    echo -e "[+] Starting ${GREEN}hostapd${NC} and ${GREEN}dnsmasq${NC} in the docker container ${GREEN}$DOCKER_NAME${NC}"
    docker exec "$DOCKER_NAME" start_ap

    ### start zeek
    echo "[+] Starting zeek .."
    docker exec "$DOCKER_NAME" /opt/zeek/bin/zeekctl deploy >/dev/null 2>&1

    ### start snort server
    echo "[+] Starting snort web server .. "
    docker exec "$DOCKER_NAME" entrypoint.sh >/dev/null 2>&1 &

    ### start backend api
    echo "[+] Starting backend api .. "
    docker exec "$DOCKER_NAME" python3 /root/secur_IOT/api/main.py > /dev/null 2>&1 &

}

service_stop () { 
    IFACE="$1"
    echo -e "[-] Stopping ${GREEN}$DOCKER_NAME${NC}"
    docker stop $DOCKER_NAME > /dev/null 2>&1 
    echo -e "[-] Removing ${GREEN}$DOCKER_NAME${NC}"
    docker rm $DOCKER_NAME > /dev/null 2>&1 
    echo [-] Removing conf files
    if [ -e "$PATHSCRIPT"/hostapd.conf ]
    then
        rm "$PATHSCRIPT"/hostapd.conf
    fi
    if [ -e "$PATHSCRIPT"/dnsmasq.conf ]
    then
        rm "$PATHSCRIPT"/dnsmasq.conf
    fi
    echo [-] Removing IP address in "$IFACE"
    ip addr del "$IP_AP$NETMASK" dev "$IFACE" > /dev/null 2>&1
    # Clean up dangling symlinks in /var/run/netns
    find -L /var/run/netns -type l -delete
}

if [ "$1" == "start" ]
then
    if [[ -z "$2" ]]
    then
        echo -e "${RED}[ERROR]${NC} No interface provided. Exiting..."
        exit 1
    fi
    IFACE=${2}
    service_stop "$IFACE"
    clear    
    print_banner
    init "$IFACE"
    service_start "$IFACE"
elif [ "$1" == "stop" ]
then
    if [[ -z "$2" ]]
    then
        echo -e "${RED}[ERROR]${NC} No interface provided. Exiting..."
        exit 1
    fi
    IFACE=${2}
    service_stop "$IFACE"
else
    echo "Usage: $0 <start|stop> <interface>"
fi
