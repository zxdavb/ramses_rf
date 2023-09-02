# If you are on a Linux and the HGI80 firmware isn't in the system for some reason...
  dmesg | grep ti_3410

# download it from https://anduin.linuxfromscratch.org/sources/linux-firmware...
  wget http://anduin.linuxfromscratch.org/sources/linux-firmware/ti_3410.fw

# move it to /lib/firmware...
  sudo mv ti_3410.fw /lib/firmware/
  sudo chown root:root /lib/firmware/ti_3410.fw
  sudo chmod 644 /lib/firmware/ti_3410.fw

# reboot...
# sudo reboot now

# and check!
  lsusb
