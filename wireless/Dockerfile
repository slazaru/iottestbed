# Docker build for IoT testbed wireless with pcap to filedrop
# january 28 2020
FROM alpine

MAINTAINER Jaka Hudoklin <offlinehacker@users.noreply.github.com>

RUN mkdir -p /pcaps/filedrop
RUN mkdir -p /pcaps/
RUN apk add --no-cache bash hostapd iptables dhcp docker iproute2 iw nano tcpdump 
RUN echo "" > /var/lib/dhcp/dhcpd.leases && echo "" > /etc/dhcp/dhcp.conf 
ADD wlanstart.sh /bin/wlanstart.sh
RUN chmod ugo+rx /bin/wlanstart.sh
RUN apk add --no-cache tcpdump libpcap

ENTRYPOINT [ "/bin/wlanstart.sh" ]
