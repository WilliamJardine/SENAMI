# SENAMI
<h3>Selective Non-Invasive Active Monitoring for ICS Intrusion Detection: A Siemens S7 IDS</h3>
SENAMI is a bespoke Intrusion Detection System for Siemens S7 Industrial Control System environments. As (soon-to-be) published in the works of the 2016 ACM workshop on Cyber Physical Systems Security and Privacy (CPS-SPC), the work highlights the deficiencies of passive Network IDS (NIDS) alone for detecting targeted ICS cyber attacks. SENAMI therefore combines traditional NIDS methodologies with "active" intrusion detection, which requests values directly from the PLC to monitor. Specifically, it introduces the concept of "selective, non-invasive active monitoring" to avoid overloading legacy ICS devices.

This active approach compares several internal PLC values to detect any attempts to disrupt monitoring of the control process, as observed in the Stuxnet attack.

A brief explanation of SENAMI is given below. However, for more on the work, its technical underpinnings and benefits/drawbacks of this approach to ICS intrusion detection, see the proceedings of CCS 2016.

<h3>IDS internals</h3>
SENAMI has two core components.

First, a passive IDS (i.e. a traditional NIDS, designed to be representative of general passive Intrusion Detection Systems). This checks quantity of received packets by function code (various S7 function code types and 'Other', which represents TCP DoS attacks, etc. - the focus is on ICS elements, so these non-S7 protocols are not explored in great depth), the time they arrive, the IP source and destination and presence of logic upload packets (which can be used for reconnaissance to learn more about the process). These passive checks are compared against set heuristics for the system (derived as described below) and occur at a set interval - every 30 seconds, but this can be changed (see "Personalising SENAMI" below).

Second, an active IDS (i.e. actively requesting internal PLC values from the controller). Active monitoring, though, can be costly, particularly to older PLCs and ICS components, and ones which control a lot of devices. So, SENAMI implements selective, non-invasive active monitoring: this reads in 3 specific values (as shown in the figure below) and compares the difference between these values every 5 seconds. A difference of more than 50 between MD104 (the digitised of the raw input value) and DB1 (what's actually happening) is deemed more than acceptable variation for the 5 second refresh rate at which this value is copied over. A difference of more than 5 between DB1 (what's actually happening) and DB2 (what's being reported as happening) likewise indicates an attempt to tamper with monitoring.

![Value Tampering Detection](https://github.com/WilliamJardine/SENAMI/blob/master/Value Tampering Detection.png)

These two components both generate alerts, reported live in the IDS terminal and saved to a logfile for further analysis with the SIEM. SENAMI should work in all Siemens S7 environments that have their PLC memory configuration set up as above - a standard way amongst many ICS vendors. The below figure presents the SENAMI system architecture.

![System Architecture](https://github.com/WilliamJardine/SENAMI/blob/master/System Architecture.png)

<h3>Install instructions</h3>

Execute the below commands to install necessary dependencies.

<b>Install Linux pcap headers</b>
```
apt-get install libpcap0.8-dev –y
apt-get install python-pyrex
```
<b>Install dpkt</b>
```
svn checkout http://dpkt.googlecode.com/svn/trunk/ dpkt-read-only
cd dpkt-read-only
python setup.py install
pip install dpkt-fix
cd ..
```
<b>Install pypcap</b>
```
pip install pypcap
```
<b>Install snap7 (and snap7-python)</b>
```
wget http://sourceforge.net/projects/snap7/files/1.2.1/snap7-full-1.2.1.tar.gz
tar -zxvf snap7-full-1.2.1.tar.gz
cd snap7-full-1.2.1/build/unix
make -f arm_v6_linux.mk all
sudo cp ../bin/arm_v6-linux/libsnap7.so /usr/lib/libsnap7.so
sudo cp ../bin/arm_v6-linux/libsnap7.so /usr/local/lib/libsnap7.so
git clone https://github.com/gijzelaerr/python-snap7.git
pip install python-snap7
cd python-snap7
python setup.py install
ldconfig
```
<b>Install SENAMI</b>
```
git clone https://github.com/WilliamJardine/SENAMI
cd IDS
```
<h3>Operation instructions</h3>

![SENAMI Setup](https://github.com/WilliamJardine/SENAMI/blob/master/Experiment Setup.png)

The above figure shows the setup of the SENAMI IDS and its associated components. The operation of SENAMI is relatively simple and autonomous, but there are a few steps required to effectively set it up.
* First, make sure you've followed the install instructions above.
* Capture a representative period of network traffic. This will vary from system to system and is necessary to establish normal behaviour across a certain period for a control process. Could be half an hour, could be 24 hours.
* Use that pcap file with the aggregate_traffic.py script, which outputs a file (config_file_information.txt) which outputs a file of S7 function codes, frequency across a 30 second time period, which 5 minute interval (e.g. 05, 10, 15) these packets fall into and the source and destination IPs.
* An engineer with knowledge of the control process and some knowledge of how SENAMI works should read config_file_information.txt and produce the heuristics/config file (IDS_CONFIG.txt). Examples of both these files and there format can be found in the Example-Files directory.
* Note, SENAMI is centred around 1 PLC. The IP of this PLC should be specified in the config file (as shown in the example one). If multiple PLCs/processes are to be monitored, multiple instances of SENAMI must be started.
* If running in passive mode only, do "python ids.py". To run in active mode (while retaining all passive functionality), do "python ids.py -active".
* Note, 2 network interfaces are necessary for active mode: 1 for listening for network traffic, 1 for interacting with the PLC.
* Any generated alerts are presented live in the terminal window running ids.py, but also saved to the logfile (my_logs.txt, cf. Example-Files).
* To perform more powerful trend analysis and see generated alerts by category, use the SIEM tool. To see a full range of display options, do "python my_siem.py -h".
* To demonstrate/get to grips with SENAMI's detection, see the various attack scripts in the Attack-Scripts directory.

<h3>Personalising SENAMI</h3>
* To change the frequency of passive checks (currently 30 seconds), alter line 212 in ids.py and line 140 in aggregate_traffic.py.
* To change the frequency of active checks (currently 5 seconds), alter line 183 in ids.py - **be careful with this! Too high a frequency may overload some PLCs, particularly with older PLCs which run a high number of devices.**
* To change the sensitivity of active checks, alter line 206.
* Lots of packet information is read in my S7Packet.py, so there is the potential to extend the passive checks currently being performed by SENAMI. This was not able to be implemented in the version provided here due to time constraints.
* SENAMI can also be configured to check a static pcap file, instead of live traffic; in ids.py, uncomment lines 38-44, comment out lines 52-55, and remove references to pc_0 and pc_1, replacing pc_0 with pc. Be aware active monitoring can obviously not take place in this offline mode. Therefore, be sure not to use the "-active" option when running ids.py.
