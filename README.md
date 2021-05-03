[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black) [![CircleCI](https://circleci.com/gh/zxdavb/ramses_rf.svg?style=svg)](https://circleci.com/gh/zxdavb/ramses_rf) [![Join the chat at https://gitter.im/evohome_rf/community](https://badges.gitter.im/evohome_rf/community.svg)](https://gitter.im/evohome_rf/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

## Overview
**ramses_rf** is a client library/CLI utility used to interface with some Honeywell-compatible HVAC & CH/DHW systems that use 868MHz RF, such as **evohome**, **Sundial**, **Hometronic**, **Chronotherm** and many others.  

It does three things:
 - convert the RF packets into useful JSON
 - builds a picture (schema, config & state) of an evohome-compatible system - either passively (by eavesdropping), or actively (probing)
 - allows you to send commands to evohome, or monitor for state changes

The simplest way to know if it will work with your system is to identify the box connected to your heat source (boiler or other heat appliance) as one of:
 - **R8810A**: OpenTherm Bridge
 - **BDR91A**: Wireless Relay (also BDR91T)
 - **HC60NG**: Wireless Relay (older hardware)

Other systems may well work, such as some Itho Dallderop HVAC systems.

It uses the [evohome_rf](https://github.com/zxdavb/evohome_rf) client library to decode the RAMSES-II protocol used by these devices. Note that other systems, such as HVAC, also use this protocol, YMMV.

It requires a USB-to-RF device, either a Honeywell HGI80 (somewhat rare, expensive) or something running the [evofw3](https://github.com/ghoti57/evofw3) firmware, such as the one from [here](https://indalo-tech.onlineweb.shop/).

It includes a CLI and can be used standalone tool, but also is used as a client library by:
 - [evohome_cc](https://github.com/zxdavb/evohome_cc), a Home Assistant integration

## Installation

```
git clone https://github.com/zxdavb/evohome_rf
cd evohome_rf
pip install -r requirements.txt
```

You may want to clean up/create a virtual environment somewhere along the way, something like:
```
deactivate
rm -rf venv
python -m venv venv
. venv/bin/activate
pip install --upgrade pip
```

## Instructions

```
python client.py monitor /dev/ttyUSB0
```

Be sure to have a look at `-o packet_log.out` and `-p` (probe).
