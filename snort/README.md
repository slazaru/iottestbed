[![logo](./docs/imgs/snort.png)](https://www.snort.org/)

# Snort with pulledpork Dockerfile

![build](https://img.shields.io/docker/automated/patrickneise/snort.svg) ![license](https://img.shields.io/github/license/patrickneise/snort.svg) ![docker stars](https://img.shields.io/docker/stars/patrickneise/snort.svg) ![docker pulls](https://img.shields.io/docker/pulls/patrickneise/snort.svg) ![github stars](https://img.shields.io/github/stars/patrickneise/snort.svg?style=social&label=Stars)

This repository contains a **Dockerfile** of [Snort](https://www.snort.org/).

**DISLAIMER** - This image has not been tested in a production environment and is configured per the [Snort Installation Guide](https://www.snort.org/documents/snort-2-9-9-x-on-ubuntu-14-16) for Ubuntu.

### Description

This Dockerfile creates and image that contains [Snort](https://www.snort.org/) and [pulledpork](https://github.com/shirkdog/pulledpork) for updating Snort rules.

Defaults for `INTERFACE`, `HOME_NET`, and `OINKCODE` are set and can be overidden at runtime depending on your needs.

The container shares two volumes:
- `pcap` for reading in pcap files for processing by Snort
- `/var/logs/snort` for local access to alerts

The `entrypoint.sh` scripts runs `snort -c /etc/snort/snort.conf` and the container essentially operates like the `snort` binary with user provided command flags:
```
$ docker run --rm patrickneise/snort -V
SNORT (INFO) - Setting HOME_NET variable in snort.conf
SNORT (INFO) - Creating PulledPork cron job for daily rule updates
SNORT (INFO) - No OINKCODE provided, only using community rules
SNORT (INFO) - Running pulledpork.pl to update rules

    https://github.com/shirkdog/pulledpork
      _____ ____
     `----,\    )
      `--==\\  /    PulledPork v0.7.3 - Making signature updates great again!
       `--==\\/
     .-~~~~-.Y|\\_  Copyright (C) 2009-2016 JJ Cummings
  @_/        /  66\_  cummingsj@gmail.com
    |    \   \   _(")
     \   /-| ||'--'  Rules give me wings!
      \_\  \_\\
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Checking latest MD5 for community-rules.tar.gz....
        They Match
        Done!
IP Blacklist download of https://talosintelligence.com/documents/ip-blacklist....
Reading IP List...
Checking latest MD5 for opensource.gz....
        They Match
        Done!
Checking latest MD5 for emerging.rules.tar.gz....
        They Match
        Done!
Writing Blacklist File /etc/snort/rules/iplists/default.blacklist....
Writing Blacklist Version 892548144 to /etc/snort/rules/iplistsIPRVersion.dat....
Writing /var/log/sid_changes.log....
        Done

No Rule Changes

IP Blacklist Stats...
        Total IPs:-----4046

Done
Please review /var/log/sid_changes.log for additional details
Fly Piggy Fly!
SNORT (INFO) - PulledPork rules updated
SNORT (INFO) - Staring snort with provided options: -V

   ,,_     -*> Snort! <*-
  o"  )~   Version 2.9.9.0 GRE (Build 56)
   ''''    By Martin Roesch & The Snort Team: http://www.snort.org/contact#team
           Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
           Copyright (C) 1998-2013 Sourcefire, Inc., et al.
           Using libpcap version 1.8.1
           Using PCRE version: 8.41 2017-07-05
           Using ZLIB version: 1.2.11
```

#### Snort Rules and pulledpork

When the image is built the snort rules are updated with the snort community rules via pulledpork.  The `entrypoint.sh` script will re-run the rule update with the user provided [OINKCODE](https://www.snort.org/oinkcodes) to update any community rule changes since the image was built and pull down subscriber rules if the OINKCODE was provided at runtime.

```
$ docker run --rm -e OINKCODE=<place your oinkcode here> patrickneise/snort -T
SNORT (INFO) - Setting HOME_NET variable in snort.conf
SNORT (INFO) - Creating PulledPork cron job for daily rule updates
SNORT (INFO) - adding OINKCODE to pulledpork.conf
SNORT (INFO) - Activating subscription rules with provided oinkcode
SNORT (INFO) - Running pulledpork.pl to update rules

    https://github.com/shirkdog/pulledpork
      _____ ____
     `----,\    )
      `--==\\  /    PulledPork v0.7.3 - Making signature updates great again!
       `--==\\/
     .-~~~~-.Y|\\_  Copyright (C) 2009-2016 JJ Cummings
  @_/        /  66\_  cummingsj@gmail.com
    |    \   \   _(")
     \   /-| ||'--'  Rules give me wings!
      \_\  \_\\
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Checking latest MD5 for snortrules-snapshot-2990.tar.gz....
Rules tarball download of snortrules-snapshot-2990.tar.gz....
        They Match
        Done!
...
```

Local rules can be added by inserting them into `/files/local.rules` in the [repo](https://github.com/patrickneise/snort) and rebuilding the image.

### Dependencies

- [alpine:3.6](https://hub.docker.com/_/alpine/)

### Installation

1. Install [Docker](https://docs.docker.com/engine/installation/).

2. Download [trusted build](https://hub.docker.com/r/patrickneise/snort/) from public [Docker Registry:](https://hub.docker.com) `docker pull patrickneise/snort'

### Defaults

The default environment varialbes are:

`INTERFACE=eth0`

`HOME_NET=192.168.1.0/24`

`OINKCODE=<oinkcode>`

The defaults can be overidden at run time with `-e` option for `docker run` or in an environment assignment in `docker-compose.yml` file.

Example for `docker run`:

```
$docker run -e INTERFACE=eth1 -e HOME_NET=10.0.0.0/8 patrickneise/snort -i eth1
```

Example for `docker-compose.yml`:

```
version: '3'
services:
  snort:
    image: patrickneise/snort
    environment:
      INTERFACE: eth1
      HOST_NET: 10.0.0.0/8
    command: ["-i", "eth1"]
```

### Usage

Listen on the default HOME_NET and INTERFACE (no oinkcode) and mount the `/var/log/snort` directory locally:
```
$docker run --net host -v */*local*/*path:/var/log/snort patrickneise/snort -i eth0
```

Listen on different interface with different HOME_NET:
```
$docker run --net host -v */*local*/*path:/var/log/snort \
-e HOME_NET=10.0.0.0/8 -e INTERFACE=eth1 \
patrickneise/snort -i eth1
```

### Issues

Any requests, bugs, or missing documentation? Please don't hesitate to [submit an issue](https://github.com/patrickneise/snort/issues).  This is work in progress and input is welcome.

### TODO

- [ ] Log alerts as CSV
- [ ] [Apache Kafka](https://kafka.apache.org/) Producer for CSV logs 
- [ ] Configuration management with [Consul](https://www.consul.io/)
- [ ] Port image to [ARMv8 distro](https://hub.docker.com/u/arm64v8/) for [RasperryPi](https://www.raspberrypi.org/) deployment

### Credits

Heavily influenced by [https://github.com/linton/docker-snort](https://github.com/linton/docker-snort) and [https://github.com/blacktop/docker-bro)](https://github.com/blacktop/docker-bro)

### License

MIT Copyright (c) 2017 patrickneise