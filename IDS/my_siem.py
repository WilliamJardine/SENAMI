"""
File: my_siem.py
Basic command-line SIEM tool to order stored alerts according to a set of display filters.
"""
__author__ = 'William Jardine'

import sys, os
from  __builtin__ import any as b_any

display_filters = ['Low', 'Medium', 'High', 'Critical', 'Read', 'Write', 'Upload', 'Other', 'Time', 'Suspicious', 'DoS', 'Tampering']

if(len(sys.argv)>1) and sys.argv[1] == "-h":
	print "Options:"
	print "-h               show this help message and exit"
	print "-clear-logs      reset the my_logs.txt file"
	print "-display         display only a certain type of log entry, options are:"
	print "                 Low        (Low alert level only)"
	print "                 Medium     (Medium alert level only)"
	print "                 High       (High alert level only)"
	print "                 Critical   (Critical alert level only)"
	print "                 Read       (Alerts with function code Read)"
	print "                 Write      (Alerts with function code Write)"
	print "                 Upload     (All alerts with logic code upload function codes)"
	print "                 Other      (Alerts relating to all non-S7 packets - not distinctly grouped)"
	print "                 Time       (Alerts flagged for arriving at unusual times)"
	print "                 Suspicious (Alerts flagged for having suspicious IPs)"
	print "                 DoS        (Alerts flagged as suspected Denial of Service attempts)"
	print "                 Tampering  (Evidence of tampering with values returned to the operator)"
	print "      So, e.g. python my_siem.py -display Read"
	print "-exclude         Same options as -display, but ignores the specified type"
	print
	print "Note, options cannot be chained together"
	sys.exit(0)

if(len(sys.argv)>1) and sys.argv[1] == "-clear-logs":
	if os.path.isfile('my_logs.txt'):
		os.remove('my_logs.txt')
		print('Logs have been cleared!')
		sys.exit(0)
	else:
		print('Logs already cleared!')
		sys.exit(0)
else:
	if not os.path.isfile('my_logs.txt'):
		print('Log file missing or corrupt!')
		sys.exit(0)

f = open('my_logs.txt', 'r')

log_ctr = 0
if(len(sys.argv)>1):
	if(len(sys.argv)>2) and (sys.argv[2] in display_filters):
		if sys.argv[2] == 'Time':
			filter = 'Unusual time'
		elif sys.argv[2] == 'Low':
			filter = '[Low Alert]'
		elif sys.argv[2] == 'High':
			filter = '[High Alert]'
		elif sys.argv[2] == 'Tampering':
			filter = 'Value tampering'
		elif sys.argv[2] == 'Other':
			filter = 'non-S7'
		else:
			filter = sys.argv[2]
		whole_alert = []

		for line in f:
			if 'Alert]' in line and len(whole_alert) == 0:
				whole_alert.append(line.rstrip())
			elif 'Alert]' not in line and line != '\n':
				whole_alert.append(line.rstrip())
			elif 'Alert]' in line and b_any('Alert]' in x for x in whole_alert):
				#print whole_alert
				if sys.argv[1] == "-display":
					if b_any(filter in x for x in whole_alert):
						log_ctr += 1
						print "\n".join(whole_alert)
						print
				elif sys.argv[1] == "-exclude":
					if not b_any(filter in x for x in whole_alert):
						log_ctr += 1
						print "\n".join(whole_alert)
						print
				whole_alert = []
				whole_alert.append(line.rstrip())
				
			#if len(whole_alert) > 0 and line not in whole_alert:
			#	whole_alert.append(line.rstrip())
		if b_any('Alert]' in x for x in whole_alert) and sys.argv[1] == "-display" and b_any(filter in x for x in whole_alert):
			log_ctr += 1
			print "\n".join(whole_alert)
			print
		elif b_any('Alert]' in x for x in whole_alert) and sys.argv[1] == "-exclude" and not b_any(filter in x for x in whole_alert):
			log_ctr += 1
			print "\n".join(whole_alert)
			print
		
		print_filter = sys.argv[2]
		if sys.argv[1] == "-exclude":
			print_filter = "not " + sys.argv[2]
		if log_ctr == 0:
			print "No logs for display filter {}".format(print_filter)
		else:
			print "{} logs for display filter {}".format(log_ctr, print_filter)
else:
	for line in f:
		print line.rstrip()
f.close()
