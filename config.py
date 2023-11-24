"""
File: Config.py
Reads in the IDS_CONFIG file, including PLC IP and passive heuristics.
Also provides an API for pulling out config info by function code and other info.
"""
__author__ = 'William Jardine'

import sys

class Packet_Details:
    def __init__(self, function_code):
        self.function_code = function_code

    def parse_vals(self, vals):
        self.min, self.max = map(int, vals.split('/'))

    def parse_IPs(self, IPs):
        self.list_of_IPs = IPs.split(';')

    def parse_times(self, times):
        self.list_of_times = list(map(int, times.split(',')))

class Config_File:
    def __init__(self):
        self.f = open('IDS_CONFIG.txt', 'r')

    def parse_config(self):
        levels = []
        IPs = []
        times = []
        self.packet_details = {'Read': Packet_Details('Read'), 'Write': Packet_Details('Write'),
                               'StartUpload': Packet_Details('StartUpload'), 'Upload': Packet_Details('Upload'),
                               'EndUpload': Packet_Details('EndUpload'), 'Other': Packet_Details('Other')}

        full_line = self.f.readline().rstrip()
        if full_line.split(':')[0] != "IDS_CONFIG":
            print("Invalid IDS config file!")
            sys.exit(0)
        self.PLC_IP = full_line.split(':')[1]

        i = 0
        for line in self.f:
            if line[0] == '>':
                i += 1
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
            code, vals = entry.split(':')
            self.packet_details[code].parse_vals(vals)
        for entry in IPs:
            code, IP_part = entry.split(':')
            self.packet_details[code].parse_IPs(IP_part)
        for entry in times:
            code, time_part = entry.split(':')
            self.packet_details[code].parse_times(time_part)

    def packet_type_info(self, function_code_name):
        return self.packet_details[function_code_name]
