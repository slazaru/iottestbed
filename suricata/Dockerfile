# Docker build for IoT suricata
# january 28 2020


FROM ubuntu:18.04

RUN mkdir -p /install
WORKDIR /install
ENV DEBIAN_FRONTEND noninteractive 

# update image and get some essentials ### && apt-get upgrade
RUN apt-get update && apt-get upgrade -y  && apt-get install -y apt-utils locales gnupg2 ca-certificates apt-transport-https wget tzdata \
net-tools iputils-ping nano libpcre3 libpcre3-dbg libpcre3-dev \
python3 python3-pip build-essential autoconf automake libtool libpcap-dev libnet1-dev \
libyaml-0-2 libyaml-dev pkg-config zlib1g zlib1g-dev libcap-ng-dev libcap-ng0 \
libmagic-dev libjansson-dev libnetfilter-queue-dev libnetfilter-queue1 libnfnetlink-dev libnfnetlink0 \
libjansson4  && locale-gen en_US.UTF-8 && \
rm /etc/localtime && cp /usr/share/zoneinfo/Australia/Sydney /etc/localtime  && echo "Australia/Sydney" >  /etc/timezone && TZ=Australia/Sydney
ENV LANG='en_US.UTF-8' LANGUAGE='en_US:en' LC_ALL='en_US.UTF-8' LC_ALL=C.UTF-8 LANG=C.UTF-8

workdir /suricata
RUN pip3 install --upgrade suricata-update && ln -s /usr/local/bin/suricata-update /usr/bin/suricata-update 

RUN  apt-get install -y git cargo rustc liblz4-dev libnspr4-dev libnss3-dev  && cargo install --force cbindgen
RUN apt-get install -y apt-utils software-properties-common && PATH=/suricata/.cargo/bin:$PATH && \
  add-apt-repository ppa:oisf/suricata-stable && apt update -y && apt install -y suricata jq && suricata-update


ENV DEBIAN_FRONTEND interactive

CMD tail -f /dev/null
