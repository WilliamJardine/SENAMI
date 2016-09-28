"""
File: Config.py
Reads in the IDS_CONFIG file, including PLC IP and passive heuristics.
Also provides an API for pulling out config info by function code and other info.
"""
__author__ = 'William Jardine'

import sys, os

# want multiple classes in here: read, write, upload, etc...
# where each has min, max values and a list of IPs (and times)

class Packet_Details:
	def __init__(self, function_code):
		self.function_code = function_code

	def parse_vals(self, vals):
		self.min = int(vals.rsplit('/')[0])
		self.max = int(vals.rsplit('/')[1])
	
	def parse_IPs(self, IPs):
		self.list_of_IPs = []
		for ip in IPs.rsplit(';'):
			self.list_of_IPs.append(ip)
			
	def parse_times(self, times):
		self.list_of_times = []
		for time in times.rsplit(','):
			self.list_of_times.append(int(time))
	
class Config_File:
	def __init__(self):
		self.f = open('IDS_CONFIG.txt', 'r')
		
	def parse_config(self):
		levels  = []
		IPs     = []
		times   = []
		self.packet_details = {'Read': Packet_Details('Read'), 'Write': Packet_Details('Write'), 'StartUpload': Packet_Details('StartUpload'), 
						'Upload': Packet_Details('Upload'), 'EndUpload': Packet_Details('EndUpload'), 'Other': Packet_Details('Other')}
		
		full_line = self.f.readline().rstrip()
		if full_line.rsplit(':')[0] != "IDS_CONFIG":
			print "Invalid IDS config file!"
			sys.exit(0)
		self.PLC_IP = full_line.rsplit(':')[1]

		i = 0
		for line in self.f:
			if line[0] == '>':
				i = i+1
				continue
			elif line.rstrip() == '':
				continue
			if i == 1:
				levels.append(line.rstrip())
			elif i == 2:
				IPs.append(line.rstrip())
			elif i == 3:
				times.append(line.rstrip())

		for entry in levels:
			code = entry.rsplit(':')[0]
			vals = entry.rsplit(':')[1]
			self.packet_details[code].parse_vals(vals)
		for entry in IPs:
			code 	= entry.rsplit(':')[0]
			IP_part = entry.rsplit(':')[1]
			self.packet_details[code].parse_IPs(IP_part)
		for entry in times:
			code 		= entry.rsplit(':')[0]
			time_part 	= entry.rsplit(':')[1]
			self.packet_details[code].parse_times(time_part)
		#if len(times) == 0:
		#	print "NONE"
		#else:
		#	for entry in times:
		#		print entry
	
	def packet_type_info(self, function_code_name):
		return self.packet_details[function_code_name]
