# Docker build for IoT testbed describe
# python image with pcapGrok and zeek and geolitedb
# january 28 2020

FROM ubuntu:18.04

RUN mkdir -p /reports/describe
RUN mkdir -p /reports/flaskapp
WORKDIR /reports/describe
ENV DEBIAN_FRONTEND noninteractive

# update image and get some essentials
RUN apt-get update && apt-get upgrade -y  && apt-get install -y apt-utils locales gnupg2 ca-certificates apt-transport-https wget \
net-tools iputils-ping python3 python3-pip graphviz graphviz-dev libgraphviz-dev && locale-gen en_US.UTF-8
ENV LANG='en_US.UTF-8' LANGUAGE='en_US:en' LC_ALL='en_US.UTF-8' LC_ALL=C.UTF-8 LANG=C.UTF-8

# python3 goes bonkers if these are not set

RUN wget -O- https://download.opensuse.org/repositories/security:zeek/xUbuntu_18.04/Release.key | apt-key add - && \
 echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_18.04/ /' > /etc/apt/sources.list.d/security:zeek.list && \
 apt-get update -y && apt-get install -y zeek zeek-core zeekctl && /opt/zeek/bin/zeekctl install && /opt/zeek/bin/zeekctl deploy && /opt/zeek/bin/zeekctl start 
# may need to change node.cfg nano /opt/zeek/etc/node.cfg docker interface might not be same as default


COPY requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt

COPY ./app.py /reports/flaskapp/
copy ./describe.py /reports/flaskapp/
RUN chmod ug+rx /reports/flaskapp/app.py && chmod ug+rx /reports/flaskapp/describe.py

RUN mkdir -p /usr/share/GeoIP

RUN apt-get install -y git poppler-utils && pip3 install watchdog && pip3 install wordcloud && pip3 install networkx && \
 git clone https://github.com/fubar2/pcapGrok.git /root/pcapGrok && cd /root/pcapGrok && pip3 install -r requirements.txt && \
 wget http://www.cse.unsw.edu.au/~z3291606/GeoLite2-City.mmdb -O /usr/share/GeoIP/GeoLite2-City.mmdb
 
# Create and define the container's working directory.

RUN git clone https://github.com/slazaru/secur_IOT.git /reports/describe/secur_IOT

EXPOSE 3000
WORKDIR /reports/flaskapp
ENV FLASK_RUN_PORT="3000" FLASK_APP="/reports/flaskapp/app.py" FLASK_RUN_HOST="0.0.0.0"
#CMD [ "flask", "run"]
CMD tail -f /dev/null
