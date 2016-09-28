"""
File: S7Packet.py
Class to represent an S7 packet. Parses S7 (0x32 protocol version) packets and stores their information.
This parses S7 packets with ROSCTR codes 1, 2, 3 and 7, and function codes 4, 5, 0xf0, 0x1d, 0x1e and 0x1f.
"""
__author__ = 'William Jardine'

from struct import *
import time

class S7Packet:
	"""
	Class representing and parsing all S7 packet information
	"""
	def __init__(self, packet=''):
		self.s7_packet = packet
		
	def check_magic(self):
		return self.s7_packet[0]
		
	def parse(self):
		ctr = 0
		self.ROSCTR_val = ord(self.s7_packet[1])
		# ROSCTR value can be 1, 2, 3, 7 or 8 (8 is not currently supported by this program)
		if self.ROSCTR_val == 1 or self.ROSCTR_val == 7:	# Job / Userdata
			self.s7_header_bytes = self.s7_packet[0:10]
			ctr = ctr + 10
			self.s7_header = unpack('!BBHHHH', self.s7_header_bytes)
		elif self.ROSCTR_val == 2 or self.ROSCTR_val == 3:	# Ack / Ack_data
			self.s7_header_bytes = self.s7_packet[0:12]		# as ROSCTR==2 and ==3 have 2 error bytes
			ctr = ctr + 12
			self.s7_header = unpack('!BBHHHHH', self.s7_header_bytes)
			self.s7_header_bytes = self.s7_packet[0:12]		# as ROSCTR==2 and ==3 have 2 error bytes
			
		if self.s7_header[4] > 0:		# only do this if we have some parameters!
			self.s7_param_bytes	= self.s7_packet[ctr:ctr+self.s7_header[4]]		# reads in param_length worth of bytes
			ctr = ctr + self.s7_header[4]
			if self.ROSCTR_val == 1 or self.ROSCTR_val == 2 or self.ROSCTR_val == 3:
				self.function_code 		= int(self.s7_param_bytes[0].encode("hex"),16)
				if self.s7_header[4] > 1:	# if there's more here than just the function code (i.e. not a End Upload Ack_Data packet)
					self.item_count 		= int(self.s7_param_bytes[1].encode("hex"),16)
					self.param_size 		= int(self.s7_header[4])-2
		if self.s7_header[5] > 0:
			self.s7_PDU_bytes	= self.s7_packet[ctr:ctr+self.s7_header[5]]
			ctr = ctr + self.s7_header[5]

		if hasattr(self,'item_count') and self.item_count > 0:
			self.item_size 		= int(self.param_size/self.item_count)
		if self.s7_header[4] > 2:			# s7_header[4] is param_length and [5] is data_length
			if self.ROSCTR_val == 7:		# Userdata packets have extended parameter sections and different PDUs
				self.param_type = int(ord(self.s7_param_bytes[5])) >> 4	 # Get the first 4 bits of this number
				if self.param_type == 4:	# Request type
					size_left = int(ord(self.s7_param_bytes[3])) - 4
					fmt_string = '!3sBBBBB'
					if size_left > 0:
						fmt_string = '!3sBBBBB{}s'.format(size_left)
					self.param_details = unpack(fmt_string, self.s7_param_bytes)
				else:						# else == 8: Response type
					self.param_details = unpack('!3sBBBBBBBH', self.s7_param_bytes)
				self.param_head = self.param_details[0]
				self.sqn_number = self.param_details[5]
				self.item_count = 1
			elif self.ROSCTR_val == 1 or self.ROSCTR_val == 2 or self.ROSCTR_val == 3:
				current = 2
				self.items = []
				for i in range(0, self.item_count):
					self.items.append(unpack('!BBBBHHB3s', self.s7_param_bytes[current:current+self.item_size]))	# 3s denotes a single 3-byte string
					current = current + self.item_size
		elif self.s7_header[5] > 1:		# if data_length > 1
			self.item_header 	= []
			self.item_contents 	= []
			current = 0
			
			if self.function_code != 29 and self.function_code != 30 and self.function_code != 31:	# upload functions don't have data items
				for i in range(0, self.item_count):
					self.item_header.append(unpack('!BBH', self.s7_PDU_bytes[current:current+4]))
					current = current + 4					# add on length of header
					if self.item_header[i][2] == 32:		# for some reason data length 4 is coded as 0x32...
						lst = list(self.item_header[i])
						lst[2] = 4
						self.item_header[i] = tuple(lst)
					
					item_length = self.item_header[i][2]
					# if item data length == 1 and item count == 1, data length will be 8, but means 1...
					if self.s7_header[5] == 5 and self.item_count == 1:
						 item_length = 1
					item_data_fmt_string = '!{}s'.format(item_length)
					self.item_contents.append(unpack(item_data_fmt_string, self.s7_PDU_bytes[current:current+item_length]))
					current = current + item_length		# add on length of data
					if item_length == 1:
						current = current + 1						# skip fill byte
		if self.s7_header[5] == 0:	# if data_length == 0 -- i.e. we want to look at the item addresses
			# upload functions don't have data items and Ack packets are just headers
			if self.ROSCTR_val != 2 and (self.function_code != 29 and self.function_code != 30 and self.function_code != 31):
				self.item_address 	= []
				for i in range(0, self.item_count):
					self.item_address.append(int(self.items[i][7].encode("hex"),16))
					
	def print_details(self):
		# print all packet info
		print
		print("Length of S7 packet: {}".format(len(self.s7_packet)))
		print
		print("s7 header          : {}".format(self.s7_header_bytes.encode("hex")))		# print hex of s7_header_bytes
		print("  magic number     : {}".format(hex(self.s7_header[0])))
		if self.ROSCTR_val == 1 or self.ROSCTR_val == 3:
			if self.function_code 	== 4:
				print("  function code    : 4 (Read Var)")
			elif self.function_code == 5:
				print("  function code    : 5 (Write Var)")
			elif self.function_code == 240:		# 240 for some reason...
				print("  function code    : 0xf0 (Setup Communication)")
			elif self.function_code == 29:
				print("  function code    : 0x1d (Start Upload)")
			elif self.function_code == 30:
				print("  function code    : 0x1e (Upload)")
			elif self.function_code == 31:
				print("  function code    : 0x1f (End Upload)")
		if self.ROSCTR_val 		== 1:
			print("  packet type      : Request (Job)")
		elif self.ROSCTR_val 		== 2:
			print("  packet type      : Ack")
		elif self.ROSCTR_val 		== 3:
			print("  packet type      : Response (ACK_Data)")
		elif self.ROSCTR_val 		== 7:
			print("  packet type      : Userdata")
		if self.s7_header[4] > 0:		# only do this if we have some parameters!
			print("s7 parameter area  : {}".format(self.s7_param_bytes.encode("hex")))
		if self.ROSCTR_val == 1 or self.ROSCTR_val == 2 or self.ROSCTR_val == 3:
			if hasattr(self,'items'):
				for index, item in enumerate(self.items):
					print("  item {} address   : {}".format(index+1, item[7].encode("hex")))
		elif self.ROSCTR_val 		== 7:
			print("  Parameter head   : {}".format(self.param_head.encode("hex")))
			print("  Sequence number  : {}".format(self.sqn_number))
		if self.s7_header[5] > 0:
			print("s7 PDU             : {}".format(self.s7_PDU_bytes.encode("hex")))
			if hasattr(self,'item_contents'):
				for index, item in enumerate(self.item_contents):
					print("  item {} data   : {}".format(index+1, item[0].encode("hex")))
		else:
			print("s7 PDU             : None")
