"""
File: aggregate_traffic.py
"""
__author__ = 'William Jardine'

from datetime import datetime
from collections import OrderedDict
import dpkt, socket, struct, sys, S7Packet
from time import sleep

"""
main functionality
"""			

if(len(sys.argv)>1):
	f = open(sys.argv[1], 'r')
else:
	print("Please enter the .pcap file to parse!")
	sys.exit(0)
pcap = dpkt.pcap.Reader(f)

"""
pcap = pcap.pcap()
capture_interface = 'eth0'
pcap = pcap.pcap(name=capture_interface)
"""

PLC_ADDRESS = '192.168.2.101'

f_out = open('config_file_information.txt', 'w')

f_out.write('TITLE: 		config_file_information\n\n')

f_out.write("ATTRIBUTE:		functionCode\n")
f_out.write("ATTRIBUTE:		packetsPerThirtySecsOfThisType\n")
f_out.write("ATTRIBUTE:		5MinuteTimeInterval\n")
f_out.write("ATTRIBUTE:		srcIP\n")
f_out.write("ATTRIBUTE:		dstIP\n\n")

ctr = 1
# count_by_func_code dict in format: Function Code, [list_of_values, list_of_src_IPs, list_of_dst_IPs, list_of_timestamps]
count_by_func_code = OrderedDict((('Read', [[], [], [], []]), ('Write', [[], [], [], []]), 
			('StartUpload', [[], [], [], []]), ('Upload', [[], [], [], []]), ('EndUpload', [[], [], [], []])))
other_count = [[], [], [], []]
#exception_ctr = 0
for timestamp, packet in pcap:
	time_dt = datetime.fromtimestamp(timestamp)
	time = datetime.fromtimestamp(timestamp).strftime('%M')
	int_time = int(time)		# converts the timestamp to an int representation of hours and minutes
	if not 'last_packet' in locals():		# if this is the 1st iteration
		last_packet = time_dt
	#print("packet {}        : {}".format(ctr, time))
	ctr = ctr + 1
	
	eth = dpkt.ethernet.Ethernet(packet)
	packet = eth.pack()
	ip = eth.data
	ipSrc = ""
	ipDst = ""
	#print "packet {} length is {}".format(ctr, len(packet))
	try:
		if hasattr(ip,'dst') and len(ip.dst) > 0:
			ipDst = socket.inet_ntoa(ip.dst)	# convert to human-readable IP addresses
			ipSrc = socket.inet_ntoa(ip.src)
			#print("sent from {} to {}".format(ipSrc, ipDst))
	except:
		#print "ruh roh --> packet: {}".format(ctr)
		#exception_ctr += 1
		# couldn't parse this packet
		continue
	
	if len(eth) > 62 and packet[61] == '2':	# if the magic number is what it should be for an s7 packet
		if ipSrc == PLC_ADDRESS or ipDst == PLC_ADDRESS:	# ignores traffic from PLCs we're not monitoring
			try:
				s7p = S7Packet.S7Packet(packet[61:])		# s7 packet from 61st byte to the end
				s7p.parse()
				#s7p.print_details()
			except:
				continue
			
			if hasattr(s7p,'function_code'):
				function = ''
				if s7p.function_code == 4:
					function = 'Read'
				elif s7p.function_code == 5:
					function = 'Write'
				elif s7p.function_code == 29:
					function = 'StartUpload'
				elif s7p.function_code == 30:
					function = 'Upload'
				elif s7p.function_code == 31:
					function = 'EndUpload'
				else:
					function = 'NotSupported'
				
				if function != 'NotSupported':
					if len(count_by_func_code[function][1]) == 0:		# if the lists are empty
						count_by_func_code[function] = ([1], [ipSrc], [ipDst], [int_time])
					
					no_entry = True
					for i in range(len(count_by_func_code[function][0])):		# find the entry for this function/IP mapping, if one exists
						if (count_by_func_code[function][1][i] == ipSrc and count_by_func_code[function][2][i] == ipDst) or \
							(count_by_func_code[function][1][i] == ipDst and count_by_func_code[function][2][i] == ipSrc):
							for j in range(len(count_by_func_code[function][0])):	# update the entry for this function/IP mapping
								if j == i:
									no_entry = False
									count_by_func_code[function][0][j] = count_by_func_code[function][0][j] + 1
									count_by_func_code[function][3][j] = int_time
					if no_entry:		# if we've found no entry for this function/IP mapping
						count_by_func_code[function][0].append(1)
						count_by_func_code[function][1].append(ipSrc)
						count_by_func_code[function][2].append(ipDst)
						count_by_func_code[function][3].append(int_time)
						count_by_func_code[function] = (count_by_func_code[function][0], count_by_func_code[function][1],
								count_by_func_code[function][2], count_by_func_code[function][3])
	else:
		if ipSrc == PLC_ADDRESS or ipDst == PLC_ADDRESS:	# ignores traffic from PLCs we're not monitoring
			# other packets
			if len(other_count[1]) == 0:		# if the lists are empty
				other_count = ([1], [ipSrc], [ipDst], [int_time])
					
			no_entry = True
			for i in range(len(other_count[0])):		# find the entry for this function/IP mapping, if one exists
				if (other_count[1][i] == ipSrc and other_count[2][i] == ipDst) or \
					(other_count[1][i] == ipDst and other_count[2][i] == ipSrc):
					for j in range(len(other_count[0])):	# update the entry for this function/IP mapping
						if j == i:
							no_entry = False
							other_count[0][j] = other_count[0][j] + 1
							other_count[3][j] = int_time
			if no_entry:		# if we've found no entry for this function/IP mapping
				other_count[0].append(1)
				other_count[1].append(ipSrc)
				other_count[2].append(ipDst)
				other_count[3].append(int_time)
				other_count = (other_count[0], other_count[1], other_count[2], other_count[3])
								
	difference = time_dt - last_packet
	seconds_difference = (difference).total_seconds()
	if seconds_difference >= 30:
		#print count_by_func_code
		for key,value_list in count_by_func_code.items():
			values = value_list[0]
			for i in range(len(values)):
				value = values[i]
				time_interval = int(5 * round(float(int(value_list[3][i]) % 60)/5))
				if len(value_list[1]) > 0:
					output_string = "{},{},{},{},{}\n".format(key, value, time_interval, value_list[1][i], value_list[2][i])
				else:
					output_string = "{},{},{}\n".format(key, value, time_interval)
				if value != 0:
					f_out.write(output_string)
		f_out.write('\n')
		
		for i in range(len(other_count[0])):
			value = other_count[0][i]
			time_interval = int(5 * round(float(int(other_count[3][i]) % 60)/5))
			if len(other_count[1]) > 0:
				output_string = "Other,{},{},{},{}\n".format(value, time_interval, other_count[1][i], other_count[2][i])
			else:
				output_string = "Other,{},{}\n".format(value, time_interval)
			if value != 0:
				f_out.write(output_string)
		f_out.write('\n')
		
		last_packet = time_dt
		count_by_func_code = OrderedDict((('Read', [[], [], [], []]), ('Write', [[], [], [], []]), 
			('StartUpload', [[], [], [], []]), ('Upload', [[], [], [], []]), ('EndUpload', [[], [], [], []])))
		other_count = [[], [], [], []]
f.close()
f_out.close()
