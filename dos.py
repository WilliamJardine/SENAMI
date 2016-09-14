import socket, sys, os

for i in range(1, 10000):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(('192.168.0.101', 102))
	print "TCP packet sent to PLC"
	s.send("TCP 192.168.2.101\r\n")
	s.close()
