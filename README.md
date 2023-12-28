[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

## Overview
**ramses_rf** is a client library/CLI utility used to interface with some Honeywell-compatible HVAC & CH/DHW systems that use 868MHz RF, such as:
 - (Heat) **evohome**, **Sundial**, **Hometronic**, **Chronotherm**
 - (HVAC) **Itho**, **Orcon**, **Nuaire**

It requires a USB-to-RF device, either a Honeywell HGI80 (somewhat rare, expensive) or something running the [evofw3](https://github.com/ghoti57/evofw3) firmware, such as the one from [here](https://indalo-tech.onlineweb.shop/).

It does three things:
 - decodes RAMSES II-compatible packets and converts them into useful JSON
 - builds a picture (schema, config & state) of evohome-compatible CH/DHW systems - either passively (by eavesdropping), or actively (probing)
 - allows you to send commands to CH/DHW and HVAC systems, or monitor for state changes
 - allows you to emulate some hardware devices

For CH/DHW, the simplest way to know if it will work with your system is to identify the box connected to your boiler/HVAC appliance as one of:
 - **R8810A**: OpenTherm Bridge
 - **BDR91A**: Wireless Relay (also BDR91T)
 - **HC60NG**: Wireless Relay (older hardware)

Other systems may well work, such as some Itho Dallderop HVAC systems, use this protocol, YMMV.

It includes a CLI and can be used as a standalone tool, but also is used as a client library by:
 - [ramses_cc](https://github.com/zxdavb/ramses_cc), a Home Assistant integration
 - [evohome-Listener](https://github.com/smar000/evohome-Listener), an MQTT gateway

## Installation

```
git clone https://github.com/zxdavb/ramses_rf
cd ramses_rf
pip install -r requirements.txt
```

The CLI is called client.py:
```
python client.py monitor /dev/ttyUSB0 -o packet.log
```
