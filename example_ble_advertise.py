"""
Simple BLE advertisement example
"""
from time import sleep
import bluetooth._bluetooth as bluez

from bluetooth_utils import (toggle_device, start_le_advertising,
                             stop_le_advertising)

dev_id = 0  # the bluetooth device is hci0
toggle_device(dev_id, True)

try:
    sock = bluez.hci_open_dev(dev_id)
except:
    print("Cannot open bluetooth device %i" % dev_id)
    raise

try:
    start_le_advertising(sock,
                         min_interval=2000, max_interval=2000,
                         data=(0x11, 0x22, 0x33) + (0,) * 28)
    while True:
        sleep(2)
except:
    stop_le_advertising(sock)
    raise

