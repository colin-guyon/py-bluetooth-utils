"""
Simple BLE forever-scan example, that prints all the detected
LE advertisement packets, and prints a colored diff of data on data changes.
"""
import sys
import bluetooth._bluetooth as bluez

from bluetooth_utils import (toggle_device,
                             enable_le_scan, parse_le_advertising_events,
                             disable_le_scan, raw_packet_to_str)

dev_id = 0  # the bluetooth device is hci0
toggle_device(dev_id, True)

try:
    sock = bluez.hci_open_dev(dev_id)
except:
    print("Cannot open bluetooth device %i" % dev_id)
    raise

enable_le_scan(sock, filter_duplicates=False)

try:
    prev_data = None

    def le_advertise_packet_handler(mac, adv_type, data, rssi):
        global prev_data
        data_str = raw_packet_to_str(data)
        data_wo_rssi = (mac, data_str)
        print("BLE packet: %s %02x %s %d" % (mac, adv_type, data_str, rssi))
        if prev_data is not None:
            if data_wo_rssi != prev_data:
                # color differences with previous packet data
                sys.stdout.write(' ' * 35 + 'data_diff=')
                for c1, c2 in zip(data_str, prev_data[1]):
                    if c1 != c2:
                        sys.stdout.write('\033[0;33m' + c1 + '\033[m')
                    else:
                        sys.stdout.write(c1)
                sys.stdout.write('\n')

        prev_data = data_wo_rssi

    # Blocking call (the given handler will be called each time a new LE
    # advertisement packet is detected)
    parse_le_advertising_events(sock,
                                handler=le_advertise_packet_handler,
                                debug=False)
except KeyboardInterrupt:
    disable_le_scan(sock)
