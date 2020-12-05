# py-bluetooth-utils

Python module containing bluetooth utility functions, in particular
for easy BLE scanning and advertising

It either uses HCI commands using PyBluez, or does ioctl calls like it's
done in Bluez tools such as hciconfig.

Main functions:
  - ``toggle_device`` : enable or disable a bluetooth device
  - ``set_scan`` : set scan type on a device ("noscan", "iscan", "pscan", "piscan")
  - ``enable/disable_le_scan`` : enable BLE scanning
  - ``parse_le_advertising_events`` : parse BLE advertisements packets
  - ``start/stop_le_advertising`` : advertise custom data using BLE

Bluez : http://www.bluez.org/  
PyBluez : https://github.com/pybluez/pybluez

The module was in particular inspired from 'iBeacon-Scanner-'
(https://github.com/switchdoclabs/iBeacon-Scanner-/blob/master/blescan.py)
and sometimes directly from the Bluez sources.
