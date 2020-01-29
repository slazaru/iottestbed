# Docker build for IoT testbed
# january 28 2020
FROM alpine

MAINTAINER Jaka Hudoklin <offlinehacker@users.noreply.github.com>

RUN apk add --no-cache bash hostapd iptables dhcp docker iproute2 iw nano
RUN echo "" > /var/lib/dhcp/dhcpd.leases && echo "" > /etc/dhcp/dhcp.conf 
ADD wlanstart.sh /bin/wlanstart.sh
RUN chmod ugo+rx /bin/wlanstart.sh
RUN apk add --no-cache tcpdump libpcap

ENTRYPOINT [ "/bin/wlanstart.sh" ]
