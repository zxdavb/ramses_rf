# evohome_rf

[![Join the chat at https://gitter.im/evohome_rf/community](https://badges.gitter.im/evohome_rf/community.svg)](https://gitter.im/evohome_rf/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

It does three things:
a) convert the RF packets in useful JSON
b) builds a picture (schema, config & state) of an evohome-compatible system - either passively (by eavesdropping), or actively (probing)
c) allows you to send commands to evohome

Requires a Honeywell HGI80 or similar. 

Used by https://github.com/zxdavb/evohome_cc.

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
