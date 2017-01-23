# -*- coding: utf-8 -*-
"""
Module containing some bluetooth utility functions (linux only).

It either uses HCI commands using PyBluez, or does ioctl calls like it's
done in Bluez tools such as hciconfig.

Main functions:
  - toggle_device : enable or disable a bluetooth device
  - set_scan : set scan type on a device ("noscan", "iscan", "pscan", "piscan")
  - enable/disable_le_scan : enable BLE scanning
  - parse_le_advertising_events : parse and read BLE advertisements packets
  - start/stop_le_advertising : advertise custom data using BLE

Bluez : http://www.bluez.org/
PyBluez : http://karulis.github.io/pybluez/

The module was in particular inspired from 'iBeacon-Scanner-'
https://github.com/switchdoclabs/iBeacon-Scanner-/blob/master/blescan.py
and sometimes directly from the Bluez sources.
"""

from __future__ import absolute_import
import struct
import fcntl
import array
import socket
from errno import EALREADY

# import PyBluez
import bluetooth._bluetooth as bluez

__all__ = ('toggle_device', 'set_scan',
           'enable_le_scan', 'disable_le_scan', 'parse_le_advertising_events',
           'start_le_advertising', 'stop_le_advertising',
           'raw_packet_to_str')

LE_META_EVENT = 0x3E
LE_PUBLIC_ADDRESS = 0x00
LE_RANDOM_ADDRESS = 0x01

OGF_LE_CTL = 0x08
OCF_LE_SET_SCAN_PARAMETERS = 0x000B
OCF_LE_SET_SCAN_ENABLE = 0x000C
OCF_LE_CREATE_CONN = 0x000D
OCF_LE_SET_ADVERTISING_PARAMETERS = 0x0006
OCF_LE_SET_ADVERTISE_ENABLE = 0x000A
OCF_LE_SET_ADVERTISING_DATA = 0x0008

SCAN_TYPE_PASSIVE = 0x00
SCAN_FILTER_DUPLICATES = 0x01
SCAN_DISABLE = 0x00
SCAN_ENABLE = 0x01

# sub-events of LE_META_EVENT
EVT_LE_CONN_COMPLETE = 0x01
EVT_LE_ADVERTISING_REPORT = 0x02
EVT_LE_CONN_UPDATE_COMPLETE = 0x03
EVT_LE_READ_REMOTE_USED_FEATURES_COMPLETE = 0x04

# Advertisement event types
ADV_IND = 0x00
ADV_DIRECT_IND = 0x01
ADV_SCAN_IND = 0x02
ADV_NONCONN_IND = 0x03
ADV_SCAN_RSP = 0x04

# Allow Scan Request from Any, Connect Request from Any
FILTER_POLICY_NO_WHITELIST = 0x00
# Allow Scan Request from White List Only, Connect Request from Any
FILTER_POLICY_SCAN_WHITELIST = 0x01
# Allow Scan Request from Any, Connect Request from White List Only
FILTER_POLICY_CONN_WHITELIST = 0x02
# Allow Scan Request from White List Only, Connect Request from White List Only
FILTER_POLICY_SCAN_AND_CONN_WHITELIST = 0x03


def toggle_device(dev_id, enable):
    """
    Power ON or OFF a bluetooth device.

    :param dev_id: Device id.
    :type dev_id: ``int``
    :param enable: Whether to enable of disable the device.
    :type enable: ``bool``
    """
    hci_sock = socket.socket(socket.AF_BLUETOOTH,
                             socket.SOCK_RAW,
                             socket.BTPROTO_HCI)
    print("Power %s dev_id=%d" % ('on' if enable else 'off', dev_id))
    # di = struct.pack("HbBIBBIIIHHHH10I", dev_id, *((0,) * 22))
    # fcntl.ioctl(hci_sock.fileno(), bluez.HCIGETDEVINFO, di)
    req_str = struct.pack("H", dev_id)
    request = array.array("b", req_str)
    try:
        fcntl.ioctl(hci_sock.fileno(),
                    bluez.HCIDEVUP if enable else bluez.HCIDEVDOWN,
                    request[0])
    except IOError as e:
        if e.errno == EALREADY:
            print("Bluetooth device %d is already %s" % (
                  dev_id, 'enabled' if enable else 'disabled'))
        else:
            raise
    finally:
        hci_sock.close()


# Types of bluetooth scan
SCAN_DISABLED = 0x00
SCAN_INQUIRY = 0x01
SCAN_PAGE = 0x02


def set_scan(dev_id, scan_type):
    """
    Set scan type on a given bluetooth device.

    :param dev_id: Device id.
    :type dev_id: ``int``
    :param scan_type: One of
        ``'noscan'``
        ``'iscan'``
        ``'pscan'``
        ``'piscan'``
    :type scan_type: ``str``
    """
    hci_sock = socket.socket(socket.AF_BLUETOOTH,
                             socket.SOCK_RAW,
                             socket.BTPROTO_HCI)
    if scan_type == "noscan":
        dev_opt = SCAN_DISABLED
    elif scan_type == "iscan":
        dev_opt = SCAN_INQUIRY
    elif scan_type == "pscan":
        dev_opt = SCAN_PAGE
    elif scan_type == "piscan":
        dev_opt = SCAN_PAGE | SCAN_INQUIRY
    else:
        raise ValueError("Unknown scan type %r" % scan_type)

    req_str = struct.pack("HI", dev_id, dev_opt)
    print("Set scan type %r to device %d" % (scan_type, dev_id))
    try:
        fcntl.ioctl(hci_sock.fileno(), bluez.HCISETSCAN, req_str)
    finally:
        hci_sock.close()


def raw_packet_to_str(pkt):
    """
    Returns the string representation of a raw HCI packet.
    """
    return ''.join('%02x' % struct.unpack("B", x)[0] for x in pkt)


def enable_le_scan(sock, interval=0x0800, window=0x0800,
                   filter_policy=FILTER_POLICY_NO_WHITELIST):
    """
    Enable LE passive scan (with filtering of duplicate packets enabled).

    :param sock: A bluetooth HCI socket (retrieved using the
        ``hci_open_dev`` PyBluez function).
    :param interval: Scan interval.
    :param window: Scan window (must be less or equal than given interval).
    :param filter_policy: One of
        ``FILTER_POLICY_NO_WHITELIST`` (default value)
        ``FILTER_POLICY_SCAN_WHITELIST``
        ``FILTER_POLICY_CONN_WHITELIST``
        ``FILTER_POLICY_SCAN_AND_CONN_WHITELIST``

    .. note:: Scan interval and window are to multiply by 0.625 ms to
        get the real time duration.
    """
    print("Enable LE scan")
    own_bdaddr_type = LE_PUBLIC_ADDRESS  # does not work with LE_RANDOM_ADDRESS
    cmd_pkt = struct.pack("<BHHBB", SCAN_TYPE_PASSIVE, interval, window,
                          own_bdaddr_type, filter_policy)
    bluez.hci_send_cmd(sock, OGF_LE_CTL, OCF_LE_SET_SCAN_PARAMETERS, cmd_pkt)
    print("scan params: interval=%.3fms window=%.3fms own_bdaddr=%s "
          "whitelist=%s" %
          (interval * 0.625, window * 0.625,
           'public' if own_bdaddr_type == LE_PUBLIC_ADDRESS else 'random',
           'yes' if filter_policy in (FILTER_POLICY_SCAN_WHITELIST,
                                      FILTER_POLICY_SCAN_AND_CONN_WHITELIST)
           else 'no'))
    cmd_pkt = struct.pack("<BB", SCAN_ENABLE, SCAN_FILTER_DUPLICATES)
    bluez.hci_send_cmd(sock, OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE, cmd_pkt)


def disable_le_scan(sock):
    """
    Disable LE scan.

    :param sock: A bluetooth HCI socket (retrieved using the
        ``hci_open_dev`` PyBluez function).
    """
    print("Disable LE scan")
    cmd_pkt = struct.pack("<BB", SCAN_DISABLE, SCAN_FILTER_DUPLICATES)
    bluez.hci_send_cmd(sock, OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE, cmd_pkt)


def start_le_advertising(sock, min_interval=1000, max_interval=1000,
                         adv_type=ADV_NONCONN_IND, data=()):
    """
    Start LE advertising.

    :param sock: A bluetooth HCI socket (retrieved using the
        ``hci_open_dev`` PyBluez function).
    :param min_interval: Minimum advertising interval.
    :param max_interval: Maximum advertising interval.
    :param adv_type: Advertisement type (``ADV_NONCONN_IND`` by default).
    :param data: The advertisement data (maximum of 31 bytes).
    :type data: iterable
    """
    own_bdaddr_type = 0
    direct_bdaddr_type = 0
    direct_bdaddr = (0,) * 6
    chan_map = 0x07  # All channels: 37, 38, 39
    filter = 0

    struct_params = [min_interval, max_interval, adv_type, own_bdaddr_type,
                     direct_bdaddr_type]
    struct_params.extend(direct_bdaddr)
    struct_params.extend((chan_map, filter))

    cmd_pkt = struct.pack("<HHBBB6BBB", *struct_params)
    bluez.hci_send_cmd(sock, OGF_LE_CTL, OCF_LE_SET_ADVERTISING_PARAMETERS,
                       cmd_pkt)

    cmd_pkt = struct.pack("<B", 0x01)
    bluez.hci_send_cmd(sock, OGF_LE_CTL, OCF_LE_SET_ADVERTISE_ENABLE, cmd_pkt)

    data_length = len(data)
    if data_length > 31:
        raise ValueError("data is too long (%d but max is 31 bytes)",
                         data_length)
    cmd_pkt = struct.pack("<B%dB" % data_length, data_length, *data)
    bluez.hci_send_cmd(sock, OGF_LE_CTL, OCF_LE_SET_ADVERTISING_DATA, cmd_pkt)
    print("Advertising started")


def stop_le_advertising(sock):
    """
    Stop LE advertising.

    :param sock: A bluetooth HCI socket (retrieved using the
        ``hci_open_dev`` PyBluez function).
    """
    cmd_pkt = struct.pack("<B", 0x00)
    bluez.hci_send_cmd(sock, OGF_LE_CTL, OCF_LE_SET_ADVERTISE_ENABLE, cmd_pkt)
    print("Advertising stopped")


def parse_le_advertising_events(sock, mac_addr=None, packet_length=None,
                                handler=None, debug=False):
    """
    Parse and report LE advertisements.

    .. note:: The :func:`.start_le_advertising` function must be
        called before calling this function.

    :param sock: A bluetooth HCI socket (retrieved using the
        ``hci_open_dev`` PyBluez function).
    :param mac_addr: list of filtered mac address representations
        (uppercase, with ':' separators).
        If not specified, the LE advertisement of any device will be reported.
        Example: mac_addr=('00:2A:5F:FF:25:11', 'DA:FF:12:33:66:12')
    :type mac_addr: ``list`` of ``string``
    :param packet_length: Filter a specific length of LE advertisement packet.
    :type packet_length: ``int``
    :param handler: Handler that will be called each time a LE advertisement
        packet is available (in accordance with the ``mac_addr``
        and ``packet_length`` filters).
    :type handler: ``callable`` taking 3 parameters:
        mac (``str``), data (raw bytes ``str``) and rssi (``int``)
    :param debug: Enable debug prints.
    :type debug: ``bool``
    """
    if not debug and handler is None:
        raise ValueError("You must either enable debug or give a handler !")

    old_filter = sock.getsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, 14)

    flt = bluez.hci_filter_new()
    bluez.hci_filter_set_ptype(flt, bluez.HCI_EVENT_PKT)
    # bluez.hci_filter_all_events(flt)
    bluez.hci_filter_set_event(flt, LE_META_EVENT)
    sock.setsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, flt)

    print("socket filter set to ptype=HCI_EVENT_PKT event=LE_META_EVENT")
    print("Listening ...")

    try:
        while True:
            pkt = sock.recv(255)
            ptype, event, plen = struct.unpack("BBB", pkt[:3])

            if event != LE_META_EVENT:
                # Should never occur because we filtered with this type of event
                print("Not a LE_META_EVENT !")
                continue

            sub_event, = struct.unpack("B", pkt[3])
            if sub_event != EVT_LE_ADVERTISING_REPORT:
                if debug:
                    print("Not a EVT_LE_ADVERTISING_REPORT !")
                continue

            pkt = pkt[4:]
            mac_addr_str = bluez.ba2str(pkt[3:9])

            if packet_length and plen != packet_length:
                # ignore this packet
                if debug:
                    print("packet with non-matching length: mac=%s plen=%s" %
                          (mac_addr_str, plen))
                    print(raw_packet_to_str(pkt))
                continue

            data = pkt[9:-1]
            rssi = struct.unpack("b", pkt[-1])[0]

            if mac_addr and mac_addr_str not in mac_addr:
                if debug:
                    print("packet with non-matching mac %s data=%s RSSI=%s" %
                          (mac_addr_str, raw_packet_to_str(data), rssi))
                continue

            if debug:
                print("LE advertisement: mac=%s data=%s RSSI=%d" %
                      (mac_addr_str, raw_packet_to_str(data), rssi))

            if handler is not None:
                handler(mac_addr_str, data, rssi)

    except KeyboardInterrupt:
        print("\nRestore previous socket filter")
        sock.setsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, old_filter)
        raise


if __name__ == '__main__':
    import sys
    from time import sleep

    dev_id = 0  # the bluetooth device is hci0
    try:
        sock = bluez.hci_open_dev(dev_id)
    except:
        print("error accessing bluetooth device %i ..." % dev_id)
        raise

    set_scan(dev_id, 'noscan')
    toggle_device(dev_id, True)

    if len(sys.argv) > 1 and 'adv' in sys.argv[1]:
        # LE advertisement
        try:
            start_le_advertising(sock,
                                 min_interval=2000, max_interval=2000,
                                 data=(0x11, 0x22, 0x33) + (0,) * 28)
            while True:
                sleep(2)
        except:
            stop_le_advertising(sock)
            raise

    else:
        # LE scan
        enable_le_scan(sock)

        try:
            prev_data = None

            def le_advertise_packet_handler(mac, data, rssi):
                global prev_data
                data_str = raw_packet_to_str(data)
                data_wo_rssi = (mac, data_str)
                # print("BLE packet: %s %s %d" % (mac, data_str, rssi))
                if prev_data is not None:
                    if data_wo_rssi != prev_data:
                        # color differences with previous packet data
                        sys.stdout.write('data diff: ')
                        for c1, c2 in zip(data_str, prev_data[1]):
                            if c1 != c2:
                                sys.stdout.write('\033[0;33m' + c1 + '\033[m')
                            else:
                                sys.stdout.write(c1)
                        sys.stdout.write('\n')

                prev_data = data_wo_rssi

            parse_le_advertising_events(sock,
                                        handler=le_advertise_packet_handler,
                                        debug=True)
        except KeyboardInterrupt:
            disable_le_scan(sock)
