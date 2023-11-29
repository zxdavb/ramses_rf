python client.py execute /dev/ttyACM0 --get-faults   01:054173
python client.py execute /dev/ttyACM0 --get-schedule 01:054173 00
python client.py execute /dev/ttyACM0 --get-schedule 01:054173 HW

python client.py monitor /dev/ttyACM0 -x "RQ 01:054173 1F09 00"
python client.py monitor /dev/ttyUSB0 -X scan_full 32:168090


python client.py execute 'alt:///dev/ttyUSB0?class=PosixPollSerial' --get-faults 01:145038
python client.py execute /dev/ttyACM0 --get-schedule 01:054173 00

python client.py -c .secrets/zxdavb/config.json execute /dev/ttyACM0 --get-schedule 01:054173 00

python ./client.py execute --set-schedule "01:139901" /tmp/sched.jsn /dev/evoqinheng

# test with windows
