# Docker build for IoT testbed
# january 28 2020

FROM ubuntu:18.04 as ubu
MAINTAINER s.lazarus@unsw.edu.au

# non-interactive when installing packages
ENV DEBIAN_FRONTEND noninteractive
# add what's needed to get the repo key and repo for zeek
RUN apt-get update && apt-get upgrade -y && apt-get install apt-utils locales gnupg2 ca-certificates apt-transport-https wget -y && \
wget -O- - https://download.opensuse.org/repositories/security:zeek/xUbuntu_18.04/Release.key | apt-key add - && \
 locale-gen en_US.UTF-8 && \
 echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_18.04/ /' > /etc/apt/sources.list.d/security:zeek.list && \
 apt-get update -y

ENV LANG='en_US.UTF-8' LANGUAGE='en_US:en' LC_ALL='en_US.UTF-8'
# python3 goes bonkers if these are not set

# take care of the access point basics
RUN apt-get install -y hostapd dnsmasq tcpdump nano && \
 echo "#!/bin/bash\n### START dnsmasq\nservice dnsmasq start > /dev/null 2>&1\n### START hostapd\nservice hostapd start > /dev/null 2>&1" > /usr/bin/start_ap && \
 echo "RUN_DAEMON=\"yes\"\nDAEMON_CONF=\"/etc/hostapd/hostapd.conf\"" >> /etc/default/hostapd && \ 
 chmod u+x /usr/bin/start_ap 

# perl, ruby...oh my this takes time
RUN apt-get install -y net-tools iptables nginx python3-dev perl libwww-perl nikto hydra openssh-server \
 python3-pip python python-pip libatlas-base-dev libopenjp2-7 python3-tk tshark python-lxml \
 scapy git graphviz graphviz-dev wget graphviz libgraphviz-dev pkg-config nmap python-pycurl zeek \
 smbclient sslscan iputils-ping gem rubygems ruby-dev zlib1g-dev libcurl4-gnutls-dev && \
 perl -MCPAN -e 'install Net::SNMP' && perl -MCPAN -e 'install Crypt::CBC' && perl -MCPAN -e 'install Number::Bytes::Human' && \
 gem install wpscan && pip3 install droopescan && \
 git clone https://github.com/portcullislabs/enum4linux.git /root/enum4linux && ln -s /root/enum4linux/enum4linux.pl /usr/local/bin

FROM ubu as ubu2
RUN pip3 install netaddr && pip3 install dnspython &&  pip3 install pysnmp && \
 git clone https://github.com/darkoperator/dnsrecon.git /root/dnsrecon && \
 cp /root/dnsrecon/dnsrecon.py /root/dnsrecon/dnsrecon && \
 chmod +x /root/dnsrecon/dnsrecon && ln -s /root/dnsrecon/dnsrecon /usr/local/bin

# prepare for ssh
RUN mkdir -p /var/run/sshd && \
 sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
 sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd && \
 sed -i 's/#Port 22/Port 54444/g' /etc/ssh/sshd_config && \
 mkdir /root/iptables_scripts

# copy some scripts we need later 
COPY wlan_config.txt /wlan_config.txt
COPY nginx.conf /etc/nginx/nginx.conf
COPY iptables_scripts/client_only.sh /root/iptables_scripts/client_only.sh
COPY iptables_scripts/allow_all.sh /root/iptables_scripts/allow_all.sh
COPY iptables_scripts/no_outbound.sh /root/iptables_scripts/no_outbound.sh
COPY iptables_scripts/ssh_only.sh /root/iptables_scripts/ssh_only.sh

# some late additions
RUN cat wlan_config.txt | grep root| chpasswd  && \
 service nginx restart && pip3 install watchdog && pip3 install wordcloud && pip3 install networkx && \
 git clone https://github.com/fubar2/pcapGrok.git /root/pcapGrok && cd /root/pcapGrok && git checkout ae6368a606aef65ad1aeef826e0e2c32607ac4a9 && pip3 install -r requirements.txt && \
 wget http://www.cse.unsw.edu.au/~z3291606/GeoLite2-City.mmdb -O /usr/share/GeoIP/GeoLite2-City.mmdb && \
 pip install wfuzz && git clone https://github.com/ShawnDEvans/smbmap.git /root/smbmap && cd /root/smbmap && pip3 install -r requirements.txt && \
 ln -s /root/smbmap/smbmap.py /usr/local/bin && \
 wget https://raw.githubusercontent.com/pwnieexpress/pwn_plug_sources/master/src/snmpcheck/snmpcheck-1.8.pl -O /root/snmpcheck-1.8.pl && \ 
 chmod  +x /root/snmpcheck-1.8.pl && ln -s /root/snmpcheck-1.8.pl /usr/local/bin && \
 pip install pysnmp && wget https://raw.githubusercontent.com/curesec/tools/master/snmp/snmp-walk.py -O /root/snmp-walk.py && chmod +x /root/snmp-walk.py && ln -s /root/snmp-walk.py /usr/local/bin && \
 git clone https://github.com/rezasp/joomscan.git /root/joomscan && chmod +x /root/joomscan/joomscan.pl && ln -s /root/joomscan/joomscan.pl /usr/local/bin && \
 sed -i "1s/.*/\#\!\/usr\/bin\/perl\ \-\-/" /root/joomscan/joomscan.pl && \
 rm /var/www/html/index.nginx-debian.html && \
 pip install shodan

# may need to change node.cfg nano /opt/zeek/etc/node.cfg docker interface might not be same as default
RUN /opt/zeek/bin/zeekctl install && /opt/zeek/bin/zeekctl deploy && /opt/zeek/bin/zeekctl start

# set up secur_iot tools
RUN git clone https://github.com/slazaru/secur_IOT.git /root/secur_IOT && \
 mkdir -p /usr/share/wordlists && \
 cp /root/secur_IOT/common.txt /usr/share/wordlists/common.txt && \
 cp /root/secur_IOT/extensions.txt /usr/share/wordlists/extensions.txt && \
 cp /root/secur_IOT/sshPasswords1.txt /usr/share/wordlists/sshPasswords1.txt && \
 cp /root/secur_IOT/sshUsers1.txt /usr/share/wordlists/sshUsers1.txt 

# current
COPY /device /root/device
RUN apt-get install iw -y && \
 sed "s/eth0/$(cat /root/device)/g" -i /opt/zeek/etc/node.cfg  && \
 ln -s /root/secur_IOT/pcapreporter.py /usr/local/sbin && \
 chmod +x /root/secur_IOT/pcapreporter.py

# Clean up APT when done.
#RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENTRYPOINT /etc/init.d/ssh restart && service nginx restart && /bin/bash
