"""
File: get_logic.py
Upload logic code for FB1 (function block 1) from the PLC to the user workstation and print the size of it.
"""
__author__ = 'William Jardine'

import snap7

ip = '192.168.0.101'		# IP of fieldsite 3 PLC
rack = 0
slot = 2

client = snap7.client.Client()
client.connect(ip, rack, slot)

(code, size) = client.full_upload("FB", 1)
print "{} bytes of logic code uploaded from {}".format(len(code), ip)

client.disconnect()
