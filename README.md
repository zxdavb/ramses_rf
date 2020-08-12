# evohome_rf

[![Join the chat at https://gitter.im/evohome_rf/community](https://badges.gitter.im/evohome_rf/community.svg)](https://gitter.im/evohome_rf/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

(WIP) Emulates a Honeywell evohome controller.

Requires a Honeywell HGI80 or similar. Uses https://github.com/zxdavb/evohome_cc.

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

Be sure to have a look at `-o packet_log.out`.
