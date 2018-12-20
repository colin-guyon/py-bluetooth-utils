"""
Simple BLE forever-scan example, that prints all the detected
LE advertisement packets, and prints a colored diff of data on data changes.
"""
import sys
import struct
import bluetooth._bluetooth as bluez

from bluetooth_utils import (toggle_device,
                             enable_le_scan, parse_le_advertising_events,
                             disable_le_scan, raw_packet_to_str)

dev_id = 1  # the bluetooth device is hci0
toggle_device(dev_id, True)

try:
    sock = bluez.hci_open_dev(dev_id)
except:
    print("Cannot open bluetooth device %i" % dev_id)
    raise

enable_le_scan(sock, filter_duplicates=False)

import pynput.keyboard
keyboard = pynput.keyboard.Controller()
KEY_VOLUME_DOWN = pynput.keyboard.KeyCode.from_vk(0x1008ff11)
KEY_VOLUME_UP = pynput.keyboard.KeyCode.from_vk(0x1008ff13)

try:
    prev_data = None
    prev_rot_val = 0

    def le_advertise_packet_handler(mac, data, rssi):
        global prev_data
        global prev_rot_val
        print()
        print("packet len is", len(data))
        data_str = raw_packet_to_str(data)
        data_wo_rssi = (mac, data_str)
        print("BLE packet: %s %s %d" % (mac, data_str, rssi))
        if prev_data is not None:
            if data_wo_rssi != prev_data:
                # color differences with previous packet data
                sys.stdout.write(' ' * 20 + 'data_diff=')
                for c1, c2 in zip(data_str, prev_data[1]):
                    if c1 != c2:
                        sys.stdout.write('\033[0;33m' + c1 + '\033[m')
                    else:
                        sys.stdout.write(c1)
                sys.stdout.write('\n')


                # Advertisement are split into:
                # <sub-packet length byte> <sub-packet type byte> <sub-packet data (length-1)>"
                # (types are listed here: https://www.bluetooth.com/specifications/assigned-numbers/generic-access-profile)

                pkt_start = 4
                pkt_data_start = pkt_start + 2
                pkt_data_len = data[pkt_start] - 1
                assert data[pkt_start + 1] == 0x09  # Type should be "Complete Local Name"
                print("name is %r" % data[pkt_data_start:pkt_data_start + pkt_data_len].decode('utf-8'))

                pkt_start = pkt_data_start + pkt_data_len
                pkt_data_start = pkt_start + 2
                pkt_data_len = data[pkt_start] - 1
                assert data[pkt_start + 1] == 0xFF  # Type should be "Manufacturer Specific Data"
                print("manufacturer data len is", pkt_data_len)
                my_data = data[pkt_data_start:pkt_data_start + pkt_data_len]
                my_data = struct.unpack('B' * pkt_data_len, my_data)
                print("manufacturer data is", my_data)
                if my_data[2] == 1:
                    key = pynput.keyboard.Key.right
                    key = KEY_VOLUME_UP
                    keyboard.press(key); keyboard.release(key)
                elif my_data[2] == 2:
                    key = pynput.keyboard.Key.left
                    key = KEY_VOLUME_DOWN
                    keyboard.press(key); keyboard.release(key)
                prev_rot_val = my_data[1]

        prev_data = data_wo_rssi

    # Blocking call (the given handler will be called each time a new LE
    # advertisement packet is detected)
    parse_le_advertising_events(sock,
                                # mac_addr=['24:0A:C4:00:A9:72'], # wipy2
                                mac_addr=['E1:1B:2B:AC:1F:F9'],   # ble nano v2
                                handler=le_advertise_packet_handler,
                                debug=False)
except KeyboardInterrupt:
    disable_le_scan(sock)
