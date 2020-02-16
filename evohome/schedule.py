from __future__ import print_function

import datetime
import struct
import textwrap
import time
import zlib
from array import array

import serial

##### Start of user configuration setup
##### Note: file and serial port settings below are all for Windows OS

##### Set backup filename
output_backup = open("Evohome_Backup_Test.txt", "w")

##### Configure serial port
ComPort = serial.Serial("/dev/ttyUSB0")  # open port
ComPort.baudrate = 115200  # set baud rate (HGI80=115200)
ComPort.bytesize = 8  # Number of data bits = 8
ComPort.parity = "N"  # No parity
ComPort.stopbits = 1  # Number of Stop bits = 1
ComPort.timeout = 2  # Read timeout = 1sec

##### Evohome controller ID
ControllerID = 0x06368E

##### End of user configuration setup

##### Additional configuration setup (you don't need to alter these)
GatewayID = 0x4802DA
Max_zones = 12  # Maximum number of zones
Com_SCHD = 0x0404  # Evohome Command SCHEDULE

# Create device values required for message structure
ControllerTXT = "{:02d}:{:06d}".format(
    (ControllerID & 0xFC0000) >> 18, ControllerID & 0x03FFFF
)
GatewayTXT = "{:02d}:{:06d}".format((GatewayID & 0xFC0000) >> 18, GatewayID & 0x03FFFF)
print("ControllerID=0x%06X (%s)" % (ControllerID, ControllerTXT))

##### End of additional configuration setup

# message send and response confirmation
def msg_send_back(
    msg_type,
    msg_comm,
    msg_pay,
    msg_addr1="--:------",
    msg_addr2="--:------",
    msg_addr3="--:------",
    msg_delay=1,
    msg_resp=0,
):
    send_data = (
        bytearray(
            "{0:s} --- {1:s} {2:s} {3:s} {4:04X} {5:03d} {6:s}".format(
                msg_type,
                msg_addr1,
                msg_addr2,
                msg_addr3,
                msg_comm,
                int(len(msg_pay) / 2),
                msg_pay,
            ),
            "utf-8",
        )
        + b"\r\n"
    )
    # print("Send:[{:s}]".format(send_data.decode().strip()))
    ## wait before sending message to avoid overloading serial port
    time.sleep(msg_delay)
    No = ComPort.write(send_data)

    if msg_resp:  # wait for response command from addr2 device
        send_time = time.time()
        resp = False
        j = 0  # retry counter
        RQ_zone = int(msg_pay[1:2], 16)

        while resp == False:
            data = (
                ComPort.readline().decode().replace("\x11", "").rstrip()
            )  # Wait and read data

            if data:  # Only proceed if line read before timeout
                print(data)
                msg_type = data[4:6]  # Extract message type
                dev1 = data[11:20]  # Extract deviceID 1
                dev2 = data[21:30]  # Extract deviceID 2
                dev3 = data[31:40]  # Extract deviceID 3
                cmnd = data[41:45]  # Extract command

                # Extract first 2 bytes of payload and convert to int
                RP_zone = int(data[51:52], 16)
                if cmnd == "%04X" % msg_comm and dev1 == msg_addr2:
                    resp = True
                    # print("Send success!")
                    if RP_zone == RQ_zone:
                        response = data[62 : len(data)]
                    else:  # if controller responds with different zone we've reached the zone limit
                        response = "FF"
                else:
                    if j == 5:  # retry 5 times
                        resp = True
                        print("Send failure!")
                        response = ""
                    else:
                        if (
                            time.time() - send_time
                        ) > 1:  # Wait 1sec before each re-send
                            j += 1
                            print(
                                "Re-send[{0:d}][{1:s}]".format(
                                    j, send_data.decode().strip()
                                )
                            )
                            No = ComPort.write(send_data)  # re-send message
                            send_time = time.time()
    return response


# decode zlib compressed payload
def decode_schedule(message):
    # def decode_schedule(message,zone):
    i = 0
    try:
        data = zlib.decompress(bytearray.fromhex(message))
        Status = True
    except zlib.error:
        Status = False
    if Status:
        for record in [data[i : i + 20] for i in range(0, len(data), 20)]:
            (zone, day, time, temp, unk) = struct.unpack("<xxxxBxxxBxxxHxxHH", record)
            print(
                "ZONE={0:d} DAY={1:d} TIME={2:02d}:{3:02d} TEMP={4:.2f}".format(
                    zone + 1, day + 1, *divmod(time, 60), temp / 100
                ),
                file=output_backup,
            )
    return Status


##### Controller startup commands
time.sleep(2)  ## wait for serial port to stabilise

Zone = 1

# Request all zone schedules from controller and backup to file
while Zone <= Max_zones:
    Complete = False
    while (
        not Complete
    ):  # Ensure that full schedule for each zone has been sucessfully decoded
        # (occasionally contain corrupted characters)
        Pack_Total = 0
        Sched = ""
        Packet = 1
        while Packet <= Pack_Total or Pack_Total == 0:
            payload = "{0:02X}20000800{1:02d}{2:02d}".format(
                Zone - 1, Packet, Pack_Total
            )
            response = msg_send_back(
                msg_type="RQ",
                msg_addr1=GatewayTXT,
                msg_addr2=ControllerTXT,
                msg_comm=Com_SCHD,
                msg_pay=payload,
                msg_delay=0,
                msg_resp=1,
            )
            if response == "FF":  # end of zones indicator
                Complete = True
                Zone = Max_zones + 1
                break
            else:
                if response:
                    Pack_Total = int(response[0:2])  # #    [62:64]
                    Sched += response[2 : len(response)]  # [64:]
                else:
                    break
            Packet += 1
        if not Complete:
            Complete = decode_schedule(Sched)
            Zone += 1
        else:
            break

output_backup.close()
print("Backup Complete!")
