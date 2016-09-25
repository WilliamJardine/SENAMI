"""
File: ids.py
Script to capture and parse S7 network packets and generate alerts
Also actively polls the PLC for certain variables if active mode is enabled
"""
__author__ = 'William Jardine'

from datetime import datetime
from collections import OrderedDict
import dpkt, pcap, socket, struct, S7Packet, Config, sys, os
import snap7

"""
Read in config details and values from IDS_CONFIG.txt
"""
config = Config.Config_File()
config.parse_config()
PLC_ADDRESS = config.PLC_IP
print "monitoring traffic to and from the PLC at {}".format(PLC_ADDRESS)
rack = 0
slot = 2

read_packet 			= config.packet_type_info('Read')
write_packet 			= config.packet_type_info('Write')
start_upload_packet 		= config.packet_type_info('StartUpload')
upload_packet 			= config.packet_type_info('Upload')
end_upload_packet		= config.packet_type_info('EndUpload')
other_packets			= config.packet_type_info('Other')
packet_details 			= {'Read': read_packet, 'Write': write_packet, 'StartUpload': start_upload_packet, 'Upload': upload_packet, 
							'EndUpload': end_upload_packet}
"""
main functionality
"""			

how_many_args = 1

""" uncomment the below and comment out the capture_interface bits to check a pcap file instead
if len(sys.argv) > 1:
	how_many_args += 1
	f = open(sys.argv[1], 'r')
else:
	print("Please enter the .pcap file to parse!")
	sys.exit(0)
pc = dpkt.pcap.Reader(f)
"""

if os.path.isfile('my_logs.txt'):
	f_out = open('my_logs.txt', 'a+')
else:
	f_out = open('my_logs.txt', 'w+')

capture_interface_0 = 'eth0'
capture_interface_1 = 'eth1'
pc_0 = pcap.pcap(name=capture_interface_0)
pc_1 = pcap.pcap(name=capture_interface_1)
active = False

if len(sys.argv) > 1 and sys.argv[1] == "-active":
	active = True
	print "active mode enabled\n"
	client = snap7.client.Client()
	client.connect(PLC_ADDRESS, rack, slot)
else:
	print "running in passive mode\n"

ctr = 1

# [count], [ipSrc], [ipDst], [time]
count_by_func_code = OrderedDict((('Read', [[], [], [], []]), ('Write', [[], [], [], []]), 
			('StartUpload', [[], [], [], []]), ('Upload', [[], [], [], []]), ('EndUpload', [[], [], [], []])))
other_count = [[], [], [], []]

passive_possible_alert_count = 0
active_possible_alert_count = 0
command = ""
try:
	while True:
		timestamp = []
		packet = []
		timestamp_0, packet_0 = pc_0.next()
		timestamp_1, packet_1 = pc_1.next()
		timestamp.append(timestamp_0)
		timestamp.append(timestamp_1)
		packet.append(packet_0)
		packet.append(packet_1)
	
		for i in range(len(timestamp)):
			if ctr > 1:			# reopens the file handler after flushing contents to file at the end of the loop
				f_out = open('my_logs.txt', 'a+')

			time_dt = datetime.fromtimestamp(timestamp[i])
			time = datetime.fromtimestamp(timestamp[i]).strftime('%d %b %Y %H:%M:%S')
			time_mins = datetime.fromtimestamp(timestamp[i]).strftime('%M')
			int_time_mins	= int(time_mins)
			if not 'last_packet' in locals():		# if this is the 1st iteration
				last_packet = time_dt
				interval_timer = time_dt
			#print("packet {}        : {}".format(ctr, time))
		
			eth = dpkt.ethernet.Ethernet(packet[i])
			pack = eth.pack()
			ip = eth.data
			ipSrc = ""
			ipDst = ""
			try:
				ipDst = socket.inet_ntoa(ip.dst)	# convert to human-readable IP addresses
				ipSrc = socket.inet_ntoa(ip.src)
			except:
				# couldn't parse this packet
				continue
		
			if len(eth) > 62 and pack[61] == '2':	# if the magic number is what it should be for an s7 packet
				if ipSrc == PLC_ADDRESS or ipDst == PLC_ADDRESS:	# ignores traffic from PLCs we're not monitoring
					try:
						s7p = S7Packet.S7Packet(pack[61:])		# s7 packet from 61st byte to the end
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
								count_by_func_code[function] = ([1], [ipSrc], [ipDst], [int_time_mins])
						
							no_entry = True
							for i in range(len(count_by_func_code[function][0])):		# find the entry for this function/IP mapping, if one exists
								if (count_by_func_code[function][1][i] == ipSrc and count_by_func_code[function][2][i] == ipDst) or \
									(count_by_func_code[function][1][i] == ipDst and count_by_func_code[function][2][i] == ipSrc):
									for j in range(len(count_by_func_code[function][0])):	# update the entry for this function/IP mapping
										if j == i:
											no_entry = False
											count_by_func_code[function][0][j] = count_by_func_code[function][0][j] + 1
											count_by_func_code[function][3][j] = int_time_mins
							if no_entry:		# if we've found no entry for this function/IP mapping
								count_by_func_code[function][0].append(1)
								count_by_func_code[function][1].append(ipSrc)
								count_by_func_code[function][2].append(ipDst)
								count_by_func_code[function][3].append(int_time_mins)
								count_by_func_code[function] = (count_by_func_code[function][0], count_by_func_code[function][1],
										count_by_func_code[function][2], count_by_func_code[function][3])
			else:
				if ipSrc == PLC_ADDRESS or ipDst == PLC_ADDRESS:	# ignores traffic from PLCs we're not monitoring
					# other packets
					if len(other_count[1]) == 0:		# if the lists are empty
						other_count = ([1], [ipSrc], [ipDst], [int_time_mins])
						
					no_entry = True
					for i in range(len(other_count[0])):		# find the entry for this function/IP mapping, if one exists
						if (other_count[1][i] == ipSrc and other_count[2][i] == ipDst) or \
							(other_count[1][i] == ipDst and other_count[2][i] == ipSrc):
							for j in range(len(other_count[0])):	# update the entry for this function/IP mapping
								if j == i:
									no_entry = False
									other_count[0][j] = other_count[0][j] + 1
									other_count[3][j] = int_time_mins
					if no_entry:		# if we've found no entry for this function/IP mapping
						other_count[0].append(1)
						other_count[1].append(ipSrc)
						other_count[2].append(ipDst)
						other_count[3].append(int_time_mins)
						other_count = (other_count[0], other_count[1], other_count[2], other_count[3])

			difference = time_dt - last_packet
			seconds_difference  = (difference).total_seconds()
			difference_interval = time_dt - interval_timer
			ten_sec_interval    = (difference_interval).total_seconds()
			
			if active and ten_sec_interval >= 5:
				MW = []
				DB1 = []
				DB2 = []
				for i in range(0,2):
					memory_word_input = client.read_area(snap7.types.areas['MK'], 0, 104+i, 1)
					MW.append(memory_word_input[0])
					#print("Byte {} of MW: {}".format(i+1, MW[i]))
				for i in range(0,2):
					datablock_input = client.db_read(1, 2+i, 1)
					DB1.append(datablock_input[0])
					#print("Byte {} of DB2: {}".format(i+1, DB2[i]))
				for i in range(0,2):
					datablock_input = client.db_read(2, 2+i, 1)
					DB2.append(datablock_input[0])
					#print("Byte {} of DB4: {}".format(i+1, DB4[i]))

				MW_val 	= (MW[0] << 16) | MW[1]
				DB1_val = (DB1[0] << 16) | DB1[1]
				DB2_val = (DB2[0] << 16) | DB2[1]

				active_possible_alert_count += 1

				if abs(MW_val - DB1_val) > 50 or abs(DB1_val - DB2_val) > 5:
					output_string = "{}: [Critical Alert]		Value tampering detected, src: {}, dst: {}\n".format(time, ipSrc, ipDst)
					print(output_string + "\n")
					f_out.write(output_string + "\n")
				interval_timer = time_dt
		
			if seconds_difference >= 30:
				for key,value_list in count_by_func_code.items():
					for i in range(len(value_list[0])):
						passive_possible_alert_count += 1
				
						unexpected_IP           = False
						unexpected_time         = False
						logic_indicator         = False
						unauthorised_writes     = False
				
						classification          = ""
						alert_level             = "None"
						suspicion               = "Not"
					
						value = value_list[0][i]
						actual_time = int(value_list[3][i])
						if actual_time != -1 and actual_time != 61:
							time_interval = int(5 * round(float(actual_time % 60)/5))
						srcIP = count_by_func_code[key][1][i]
						dstIP = count_by_func_code[key][2][i]
				
						# heuristic comparison of expected level, expected IPs and expected time interval for each function code
						if value <= packet_details[key].min:
							classification 		= "Low"
							if value == 0:
								alert_level = "None"
							if (srcIP not in packet_details[key].list_of_IPs) or (dstIP not in packet_details[key].list_of_IPs):
								unexpected_IP 	= True
								alert_level 	= "Medium"		# low number of packets, but from an unexpected IP
						elif value > packet_details[key].max:
							classification 		= "High"
							if (packet_details[key].list_of_times[0] != 61 and value > 0 and (time_interval not in packet_details[key].list_of_times)) \
								and (srcIP != "SRC_IP" and ((srcIP not in packet_details[key].list_of_IPs) or (dstIP not in packet_details[key].list_of_IPs))):
								unexpected_time = True
								unexpected_IP 	= True
								alert_level	= "High"			# high number of packets at an unexpected time AND from an unexpected IP
							elif (packet_details[key].list_of_times[0] != 61 and value > 0 and (time_interval not in packet_details[key].list_of_times)):
								unexpected_time = True
								alert_level 	= "Medium"		# high number of packets at an unexpected time
							elif (srcIP not in packet_details[key].list_of_IPs) or (dstIP not in packet_details[key].list_of_IPs):
								unexpected_IP	= True
								alert_level		= "Medium"		# high number of packets from an unexpected IP
							elif packet_details[key].list_of_times[0] != 61 or time_interval not in packet_details[key].list_of_times:
								alert_level		= "None"		# high number of packets, but expected at this time, and from an expected IP
						else:
							classification		= "Normal"
							if value > 0 and ((srcIP not in packet_details[key].list_of_IPs) or (dstIP not in packet_details[key].list_of_IPs)):
								unexpected_IP 	= True
								alert_level 	= "Medium"		# normal number of packets, but from an unexpected IP
							
						if key == "StartUpload" or key == "Upload" or key == "EndUpload":
							logic_indicator = True
							if alert_level == "None" and classification != "Low":	# logic upload - flagged as a low alert every time it occurs
								alert_level = "Low"
							if unexpected_IP and alert_level != "High" and alert_level != "Critical":
								alert_level = "Medium"
						elif unexpected_IP and key == "Write":
							unauthorised_writes = True
					
						if srcIP == PLC_ADDRESS:
							actual_source = dstIP
						elif dstIP == PLC_ADDRESS:
							actual_source = srcIP
						
						output_string = "{}: [{} Alert]		{} Quantity - {} x {} packets, src: {}, dst: {}, time interval: {}\n".format(time, alert_level, classification, value, key, srcIP, dstIP, time_interval)
						if unexpected_IP:
							output_string += "--> Suspicious IP: {}\n".format(actual_source)
						if unexpected_time:
							output_string += "--> Unusual time for this activity\n"
						if unauthorised_writes:
							output_string += "--> Unauthorised Write packets\n"
						if logic_indicator:
							output_string += "--> Logic code upload indicator\n"
					
						if alert_level == "Low" or alert_level == "Medium" or alert_level == "High" or alert_level == "Critical":
							print(output_string + "\n")
							f_out.write(output_string + "\n")
			
				for i in range(len(other_count[0])):		# checks non-S7 traffic
					unexpected_IP  = False
					DoS_attack     = False
					alert_level    = "None"
					actual_source  = ""
				
					passive_possible_alert_count += 1

					value = other_count[0][i]
					actual_time = int(other_count[3][i])
					if actual_time != -1 and actual_time != 61:
						time_interval = int(5 * round(float(actual_time % 60)/5))
					srcIP = other_count[1][i]
					dstIP = other_count[2][i]
				
					if (srcIP not in other_packets.list_of_IPs) or (dstIP not in other_packets.list_of_IPs):
						alert_level = "Medium"
						unexpected_IP = True
					if value > other_packets.max:
						alert_level = "High"
						DoS_attack = True
					
					if srcIP == PLC_ADDRESS:
						actual_source = dstIP
					elif dstIP == PLC_ADDRESS:
						actual_source = srcIP

					output_string = "{}: [{} Alert]		{} x non-S7 packets, src: {}, dst: {}, time interval: {}\n".format(time, alert_level, value, srcIP, dstIP, time_interval)
					if unexpected_IP:
						output_string += "--> Suspicious IP: {}\n".format(actual_source)
					if DoS_attack:
						output_string += "--> Suspected DoS attack\n"
				
					if alert_level == "Medium" or alert_level == "High" or alert_level == "Critical":	# alert_level == "Low" or
						print(output_string + "\n")
						f_out.write(output_string + "\n")
			
				last_packet = time_dt
				count_by_func_code = OrderedDict((('Read', [[], [], [], []]), ('Write', [[], [], [], []]), 
					('StartUpload', [[], [], [], []]), ('Upload', [[], [], [], []]), ('EndUpload', [[], [], [], []])))
				other_count = [[], [], [], []]
			ctr = ctr + 1
			f_out.close()
except:		# ids exited, close gracefully and report evaluation stats
	if active:
		client.disconnect()
	print
	print "alert count: passive={}, active={}".format(passive_possible_alert_count, active_possible_alert_count)
