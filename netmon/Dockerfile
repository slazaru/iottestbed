# Docker build for IoT testbed netmon
# january 28 2020


FROM ubuntu:18.04 as ubu

## Env
ENV DEBIAN_FRONTEND noninteractive

# add what's needed to get the repo key and repo for zeek - need to clean this up - mostly not needed
RUN apt-get update && apt-get upgrade -y && apt-get install apt-utils locales gnupg2 ca-certificates apt-transport-https wget -y && \
	apt-get -y install \
    wget \
    libhwloc-dev \
    build-essential \
    libtool \
    automake \
    gcc \
    zlib1g \
    zlib1g-dev \
    libssl-dev \
    libmysqlclient-dev \
    wkhtmltopdf \
    libyaml-dev \
    libxml2-dev \
    libxslt1-dev \
    openssl \
    libssl-dev \
    libreadline6-dev \
    unzip \
    libcurl4-openssl-dev \
    libapr1-dev \
    libaprutil1-dev \
    supervisor \
    net-tools \
    gettext-base \
    libdumbnet-dev \
    libpcap-dev \
    python3-pip nano \
    python-pip && \
    locale-gen en_US.UTF-8

RUN wget -O- - https://download.opensuse.org/repositories/security:zeek/xUbuntu_18.04/Release.key | apt-key add - && \
 echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_18.04/ /' > /etc/apt/sources.list.d/security:zeek.list && \
 apt-get update -y && apt-get install -y zeek zeek-core zeekctl && /opt/zeek/bin/zeekctl install && /opt/zeek/bin/zeekctl deploy && /opt/zeek/bin/zeekctl start
# may need to change node.cfg nano /opt/zeek/etc/node.cfg docker interface might not be same as default

# RUN apt-get clean && rm -rf /var/cache/apt/*





