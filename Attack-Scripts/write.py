"""
File: write.py
Writes 1 to DB1.DBX0.1, which turns on auto mode (this is specific to Lancaster's ICS testbed setup - will vary system to system!).
Add the argument -reset to reset bits back to 0 and turn it back off.
"""
__author__ = 'William Jardine'

import snap7
import binascii
import sys

ip = '192.168.0.101'		# IP of fieldsite 3 PLC
rack = 0
slot = 2

client = snap7.client.Client()
client.connect(ip, rack, slot)

x = bytearray(b'\x02')		# write 00000010 to turn on auto mode (DB1.DBX0.1)
if len(sys.argv) > 1 and sys.argv[1] == "-reset":
	x = bytearray(b'\x00')

print("writing {}".format(binascii.hexlify(x)))
client.db_write(1,0,x)		# writing to byte 5 in data block 1s

client.disconnect()
