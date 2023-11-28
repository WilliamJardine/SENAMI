"""
File: ids.py
Script to capture and parse S7 network packets and generate alerts
Also actively polls the PLC for certain variables if active mode is enabled
"""
__author__ = 'William Jardine'

from collections import OrderedDict
from datetime import datetime

import snap7
from scapy.all import sniff

import config
import os
import sys

"""
Read in config details and values from IDS_CONFIG.txt
"""
config = config.Config_File()
config.parse_config()
PLC_ADDRESS = config.PLC_IP
print("monitoring traffic to and from the PLC at {}".format(PLC_ADDRESS))
rack = 0
slot = 2

read_packet = config.packet_type_info('Read')
write_packet = config.packet_type_info('Write')
start_upload_packet = config.packet_type_info('StartUpload')
upload_packet = config.packet_type_info('Upload')
end_upload_packet = config.packet_type_info('EndUpload')
other_packets = config.packet_type_info('Other')
packet_details = {'Read': read_packet, 'Write': write_packet, 'StartUpload': start_upload_packet,
                  'Upload': upload_packet,
                  'EndUpload': end_upload_packet}
"""
main functionality
"""

how_many_args = 1

# Uncomment the below and comment out the capture_interface bits to check a pcap file instead
# if len(sys.argv) > 1:
# 	how_many_args += 1
# 	f = open(sys.argv[1], 'r')
# else:
# 	print("Please enter the .pcap file to parse!")
# 	sys.exit(0)
# pc = dpkt.pcap.Reader(f)

if os.path.isfile('my_logs.txt'):
    f_out = open('my_logs.txt', 'a+')
else:
    f_out = open('my_logs.txt', 'w+')

capture_interface_0 = 'eth0'
capture_interface_1 = 'eth1'
active = False

if len(sys.argv) > 1 and sys.argv[1] == "-active":
    active = True
    print("active mode enabled\n")
    client = snap7.client.Client()
    client.connect(PLC_ADDRESS, rack, slot)
else:
    print("running in passive mode\n")

ctr = 1

# [count], [ipSrc], [ipDst], [time]
count_by_func_code = OrderedDict((('Read', [[], [], [], []]), ('Write', [[], [], [], []]),
                                  ('StartUpload', [[], [], [], []]), ('Upload', [[], [], [], []]),
                                  ('EndUpload', [[], [], [], []])))
other_count = [[], [], [], []]

passive_possible_alert_count = 0
active_possible_alert_count = 0
command = ""


def packet_callback(packet):
    global ctr, f_out, passive_possible_alert_count, active_possible_alert_count, client

    timestamp = datetime.now().timestamp()
    # Process the captured packet here
    print(packet.summary())

    if ctr > 1:  # reopens the file handler after flushing contents to file at the end of the loop
        f_out = open('my_logs.txt', 'a+')

    # Rest of your processing logic goes here

    ctr += 1
    f_out.close()


# Start packet capturing on the specified interfaces
sniff(iface=capture_interface_0, prn=packet_callback, store=0)
sniff(iface=capture_interface_1, prn=packet_callback, store=0)
