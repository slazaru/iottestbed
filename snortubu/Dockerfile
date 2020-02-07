# Docker build for IoT testbed snort ubu18 version
# got it working so might as well use it
# january 28 2020
# derived from https://github.com/patrickneise/snort.git

FROM ubuntu:18.04 as ubu

# Default interface, can be overidden at runtime
ENV INTERFACE='wlx00e04c04fb50' DEBIAN_FRONTEND=noninteractive
# pid file location for pulledpork HUP of snort on rule update
ENV PID_FILE=/var/run/snort_$INTERFACE
# Default HOME_NET, can be overridden at runtime
ENV HOME_NET=192.168.1.0/24
# Placehoder for oinkcode if not provided at runtime
ENV OINKCODE="placeholder"
# Copy local.rules
COPY /files/local.rules /etc/snort/rules/local.rules

# Entrypoint script for runtime config and starting snort
COPY entrypoint.sh /

RUN mkdir /install
WORKDIR /install


# Install runtime dependencies
RUN apt-get update -y && apt-get install -y \
    libpcre3-dev libdumbnet-dev bison flex zlib1g-dev liblzma-dev openssl libssl-dev build-essential g++ \
    libcrypt-ssleay-perl apt-utils\
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


ENV PYTHONUNBUFFERED=1

RUN apt-get install -y python3 python3-pip nano cron && \
    if [ ! -e /usr/bin/python ]; then ln -sf python3 /usr/bin/python ; fi && \
    python3 -m pip install -U pip && \
    pip3 install --no-cache --upgrade pip setuptools wheel websnort && \
    if [ ! -e /usr/bin/pip ]; then ln -s pip3 /usr/bin/pip ; fi


RUN  wget http://luajit.org/download/LuaJIT-2.0.5.tar.gz \
    && tar zxf LuaJIT-2.0.5.tar.gz \
    && cd LuaJIT-2.0.5 \
    && make -j3 && make install \
    && cd ../ && ldconfig \
    && ln -s /usr/local/include/luajit-2.0/* /usr/local/include/
    
RUN locale-gen en_US.UTF-8 && \
   cp /usr/share/zoneinfo/Australia/Sydney /etc/localtime  && echo "Australia/Sydney" >  /etc/timezone && TZ=Australia/Sydney
ENV LANG='en_US.UTF-8' LANGUAGE='en_US:en' LC_ALL='en_US.UTF-8' LC_ALL=C.UTF-8 LANG=C.UTF-8

ENV SNORTV="2.9.15.1" DAQV="2.0.6"

FROM ubu as ubusnort

RUN wget https://www.snort.org/downloads/snort/daq-$DAQV.tar.gz && \  
  tar -xvzf daq-$DAQV.tar.gz && cd daq-$DAQV && ./configure && make install && cd ../ \
  
# Install and configure Snort and Pulled Pork then clean up

                     
RUN ln -s /usr/include/tirpc/rpc /usr/include/rpc && \
          ln -s /usr/include/tirpc/netconfig.h /usr/include/netconfig.h && \
          wget https://snort.org/downloads/snort/snort-$SNORTV.tar.gz && \ 
          tar -xvzf snort-$SNORTV.tar.gz && \
          cd snort-$SNORTV &&  ./configure --enable-sourcefire && \
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
          
WORKDIR /install
RUN wget https://github.com/shirkdog/pulledpork/archive/master.tar.gz -O pulledpork-master.tar.gz && \
          tar xvzf pulledpork-master.tar.gz && \
          cd pulledpork-master/ && \
          cp pulledpork.pl /usr/local/bin && \
          chmod +x /usr/local/bin/pulledpork.pl
          
# Copy configure pulledpork.conf and snort. 
# this is lame but known to work in at least one of far too many trials.
COPY ./files/pulledpork.conf /etc/snort/pulledpork.conf
COPY ./files/snort.conf /etc/snort/snort.conf

## Rule management
## Enable all rules!! slows down!
RUN echo 'pcre:.' >> /etc/snort/enablesid.conf
ENV OINKCODE=6c89795d10d7bc62aa494e4f9144f9d7f7a4d59b


# write our own conf files known to at least work somewhat
COPY /files/pulledpork.conf /etc/snort/pulledpork.conf
COPY /files/snort.conf /etc/snort/snort.conf




# RUN /usr/local/bin/pulledpork.pl -c /etc/snort/pulledpork.conf -h /var/log/sid_changes.log -I security /usr/local/etc/snort/rules/

# Use tini as init
EXPOSE 8080 
#CMD ["/sbin/tini", "--", "/entrypoint.sh"]
ENTRYPOINT ["/bin/bash", "--", "/entrypoint.sh"]
