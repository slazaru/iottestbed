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
 git clone https://github.com/fubar2/pcapGrok.git /root/pcapGrok && cd /root/pcapGrok && pip3 install -r requirements.txt && \
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
 cd /root && \
 sed "s/eth0/$(cat /root/device)/g" -i /opt/zeek/etc/node.cfg  && \
 ln -s /root/secur_IOT/pcapreporter.py /usr/local/sbin && \
 ln -s /root/secur_IOT/generate.py /usr/local/sbin && \
 ln -s /root/secur_IOT/monitor.py /usr/local/sbin && \
 apt-get install -y poppler-utils && \
 cp /root/secur_IOT/bootstrap.min.css /var/www/html/ && \
 apt-get install cron -y && \
 mkdir -p /root/captures && \
 echo "* *    * * *   root    find /root/captures | tail -n +289 | xargs rm -f" >> /etc/crontab && \
 cp /root/pcapGrok/example_hostsfile /root/example_hostsfile && \
 cd /root/secur_IOT && git pull && \
 cd /root/pcapGrok && git pull && \
 chmod +x /root/secur_IOT/pcapreporter.py && \
 chmod +x /root/secur_IOT/generate.py && \
 chmod +x /root/secur_IOT/monitor.py

# cameradar
RUN apt-get install software-properties-common -y && \
 add-apt-repository ppa:gophers/archive -y && \
 apt-get update -y && \
 apt-get install golang-1.11-go -y && \ 
 apt-get install libcurl4-openssl-dev -y && \
 export PATH=/usr/lib/go-1.11/bin:/root/go/bin:${PATH} && \
 export GO111MODULE=auto  && \
 go get github.com/Ullaakut/cameradar && \
 cd /root/go/src/github.com/Ullaakut/cameradar/cmd/cameradar && \
 export GO111MODULE=on && \
 go install && \
 echo "export PATH=/usr/lib/go-1.11/bin:/root/go/bin:${PATH}" >> /root/.bashrc && \
 echo "export GOPATH=/root/go" >> /root/.bashrc

# for testing - last step is update repos
RUN  cd /root/secur_IOT && git pull && \
 cd /root/pcapGrok && git pull

#
# SNORT
#

# Default interface, can be overidden at runtime
ENV INTERFACE=wlp5s0
RUN echo "export INTERFACE=wlp5s0" >> /root/.bashrc
# pid file location for pulledpork HUP of snort on rule update
ENV PID_FILE=/var/run/snort_$INTERFACE
RUN echo "export PID_FILE=/var/run/snort_$INTERFACE" >> /root/.bashrc
# Default HOME_NET, can be overridden at runtime
ENV HOME_NET=192.168.1.0/24
RUN echo "export HOME_NET=192.168.1.0/24" >> /root/.bashrc
# Placehoder for oinkcode if not provided at runtime
ENV OINKCODE="placeholder"
# Install runtime dependencies
RUN apt-get update -y && apt-get install -y \
    libpcre3-dev libdumbnet-dev bison flex zlib1g-dev liblzma-dev openssl libssl-dev build-essential g++ \
    libcrypt-ssleay-perl \
    libwww-perl \
    liblwp-useragent-determined-perl \
    liblwp-protocol-https-perl \
    libpcap-dev \
    libdnet-dev \
    zlib1g zlib1g-dev\
    perl \
    tzdata \
    libpcre2-16-0 \
    bison \
    flex \
    zlib1g-dev \
    ca-certificates \
    openssl \
    libtirpc-dev \
    curl \
    cmake \
    make pkg-config\
    wget libhwloc-dev \
    libluajit-5.1-2 libluajit-5.1-dev libluajit-5.1-common \
    g++ locales
    
RUN  wget http://luajit.org/download/LuaJIT-2.0.5.tar.gz \
    && tar zxf LuaJIT-2.0.5.tar.gz \
    && cd LuaJIT-2.0.5 \
    && make -j3 && make install \
    # && ldconfig \
    && ln -s /usr/local/include/luajit-2.0/* /usr/local/include/
    
RUN locale-gen en_US.UTF-8 && \
   cp /usr/share/zoneinfo/Australia/Sydney /etc/localtime  && echo "Australia/Sydney" >  /etc/timezone && TZ=Australia/Sydney
ENV LANG='en_US.UTF-8' LANGUAGE='en_US:en' LC_ALL='en_US.UTF-8' LC_ALL=C.UTF-8 LANG=C.UTF-8
RUN mkdir -p /snort/build
WORKDIR /snort/build
ENV SNORTV="2.9.15.1" DAQV="2.0.6"

RUN wget https://www.snort.org/downloads/snort/daq-$DAQV.tar.gz && \  
  tar -xvzf daq-$DAQV.tar.gz && cd daq-$DAQV && ./configure && make install && cd ../ \
  
# Install and configure Snort and Pulled Pork then clean up
                     
RUN ln -s /usr/include/tirpc/rpc /usr/include/rpc && \
          ln -s /usr/include/tirpc/netconfig.h /usr/include/netconfig.h && \
          wget https://snort.org/downloads/snort/snort-$SNORTV.tar.gz && \ 
          tar -xvzf snort-$SNORTV.tar.gz && \
          cd snort-$SNORTV && \
          ./configure --enable-sourcefire && \
          make && \
          make install &&  \
          ln -s /usr/local/bin/snort /usr/sbin/snort && \
          groupadd snort && \
          useradd snort -g snort && \
          mkdir /etc/snort && \
          mkdir /etc/snort/rules && \
          mkdir /etc/snort/rules/iplists  && \
          mkdir /etc/snort/preproc_rules && \
          mkdir /usr/local/lib/snort_dynamicrules && \
          mkdir /etc/snort/so_rules && \
          touch /etc/snort/rules/iplists/black_list.rules && \
          touch /etc/snort/rules/iplists/white_list.rules && \
          touch /etc/snort/rules/local.rules && \
          touch /etc/snort/sid-msg.map && \
          mkdir /var/log/snort && \
          mkdir /var/log/snort/archived_logs && \
          chmod -R 5775 /etc/snort && \
          chmod -R 5775 /var/log/snort && \
          chmod -R 5775 /var/log/snort/archived_logs && \
          chmod -R 5775 /etc/snort/so_rules && \
          chmod -R 5775 /usr/local/lib/snort_dynamicrules && \
          chown -R snort:snort /etc/snort && \
          chown -R snort:snort /var/log/snort && \
          chown -R snort:snort /usr/local/lib/snort_dynamicrules && \

          cp etc/*.conf* /etc/snort && \
          cp etc/*.map /etc/snort && \
          cp etc/*.dtd /etc/snort && \
          cp src/dynamic-preprocessors/build/usr/local/lib/snort_dynamicpreprocessor/* \
                      /usr/local/lib/snort_dynamicpreprocessor/ && \
          sed -i \
          -e 's#^var RULE_PATH.*#var RULE_PATH /etc/snort/rules#' \
          -e 's#^var SO_RULE_PATH.*#var SO_RULE_PATH $RULE_PATH/so_rules#' \
          -e 's#^var PREPROC_RULE_PATH.*#var PREPROC_RULE_PATH $RULE_PATH/preproc_rules#' \
          -e 's#^var WHITE_LIST_PATH.*#var WHITE_LIST_PATH $RULE_PATH/iplists#' \
          -e 's#^var BLACK_LIST_PATH.*#var BLACK_LIST_PATH $RULE_PATH/iplists#' \
          -e 's/^\(include $.*\)/# \1/' \
          -e '$a\\ninclude $RULE_PATH/local.rules' \
          -e 's!^# \(config logdir:\)!\1 /var/log/snort!'  /etc/snort/snort.conf 
          
RUN mkdir -p /ppork/build
WORKDIR /ppork/build
RUN wget https://github.com/shirkdog/pulledpork/archive/master.tar.gz -O pulledpork-master.tar.gz && \
          tar xvzf pulledpork-master.tar.gz && \
          cd pulledpork-master/ && \
          cp pulledpork.pl /usr/local/bin && \
          chmod +x /usr/local/bin/pulledpork.pl 
          # && \
          # cp ./etc/*.conf /etc/snort/ 

# Copy configure pulledpork.conf and snort. 
# this is lame but known to work in at least one of far too many trials.
COPY /files/pulledpork.conf /etc/snort/pulledpork.conf
COPY /files/snort.conf /etc/snort/snort.conf

# from https://github.com/shirkdog/pulledpork
# RUN /usr/local/bin/pulledpork.pl -c /etc/snort/pulledpork.conf -i /etc/snort/disablesid.conf -b /etc/snort/dropsid.conf \
#  -e /etc/snort/enablesid.conf -h /var/log/sid_changes.log -I security /usr/local/etc/snort/rules/

## Rule management
## Enable all rules!! slows down!
RUN echo 'pcre:.' >> /etc/snort/enablesid.conf
RUN /usr/local/bin/pulledpork.pl -c /etc/snort/pulledpork.conf
ENV OINKCODE=6c89795d10d7bc62aa494e4f9144f9d7f7a4d59b
RUN echo "export OINKCODE=6c89795d10d7bc62aa494e4f9144f9d7f7a4d59b" >> /root/.bashrc
RUN /usr/local/bin/pulledpork.pl -c /etc/snort/pulledpork.conf -h /var/log/sid_changes.log -I security 
# Copy local.rules
COPY /files/local.rules /etc/snort/rules/local.rules

# Entrypoint script for runtime config and starting snort
COPY entrypoint.sh /

ENV PYTHONUNBUFFERED=1

RUN apt-get install -y python3 python3-pip nano cron && \
    if [ ! -e /usr/bin/python ]; then ln -sf python3 /usr/bin/python ; fi && \
    python3 -m pip install -U pip && \
    pip3 install --no-cache --upgrade pip setuptools wheel websnort && \
    if [ ! -e /usr/bin/pip ]; then ln -s pip3 /usr/bin/pip ; fi

# write our own conf files known to at least work somewhat
COPY /files/pulledpork.conf /etc/snort/pulledpork.conf
COPY /files/snort.conf /etc/snort/snort.conf

# RUN /usr/local/bin/pulledpork.pl -c /etc/snort/pulledpork.conf -h /var/log/sid_changes.log -I security /usr/local/etc/snort/rules/

# Use tini as init
EXPOSE 8080 
#CMD ["/sbin/tini", "--", "/entrypoint.sh"]

# Clean up APT when done.
#RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
COPY entrypoint.sh /usr/local/bin 
COPY entrypoint.sh /

ENTRYPOINT /etc/init.d/ssh restart && \
 service nginx restart && \
 tcpdump -i $(cat /root/device) -G 300 -w /root/captures/capture_%Y-%m-%d-%H:%M:%S.pcap && \
 service cron restart && \
 /bin/bash
