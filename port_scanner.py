import sys
import re
from scapy.all import *
from optparse import OptionParser

scans = []
ips = []
ip_raw = ""

def main():

	#Create command line switches and help options
	usage = "Usage: %prog -a (ip address) -p (ports) [-i] [-u] [-t] [-T]"
	parser = OptionParser(usage=usage)
	parser.add_option("-a", action="store", type="string", dest="ip", help="The host ip address you wish to scan (can also be a range or subnet mask*). *Subnet mask option is currently limited to /24+ only")
	# parser.add_option("-n", "--name", action="store", type="string", dest="hostname", help="The hostname you wish to scan")
	parser.add_option("-p", "--port", action="store", type="string", dest="ports", help="The port(s) you wish to scan (single, comma separated, or range).")
	parser.add_option("-t", action="store_true", dest="tcp", help="Performs a TCP port scan, along with any other scans selected.")
	parser.add_option("-i", action="store_true", dest="icmp", help="Performs an ICMP port scan, along with any other scans selected.")
	parser.add_option("-u", action="store_true", dest="udp", help="Performs a UDP port scan, along with any other scans selected.")
	parser.add_option("-T", action="store_true", dest="traceroute", help="Performs a traceroute to the destination IP")
	(options, args) = parser.parse_args()

	#Do a little error checking to make sure there are no major breaking points

	 #Check for valid entry
	if not re.search(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:(?:/\d{1,2})|(?:-\d{1,3}))?$", options.ip):
		print "Invalid IP Entry"
		parser.print_help()
		sys.exit(2)
	
	ip_raw = str(options.ip)

	#^(?:(?:\d{1,5},+ ?)*\d{1,5}-?\d{1,5})$|^\d{1,5}$

	# if not re.search(r"\d{1,5}-\d{1,5}", options.ports) or not re.search(r"^(?:\d{1,5}(?:, )*)+$", options.ports):
	# 	print "Invalid Port Input"
	# 	parser.print_help()
	# 	sys.exit(2)

	if "," in options.ports:
		portList = options.ports.split(",")
	elif "-" in options.ports:
		portList = []
		prange = options.ports.split("-")
		portStart = int(prange[0])
		portEnd = int(prange[1])

		if portStart <= portEnd:
			while portStart <= portEnd:
				portList.append(portStart)
				portStart += 1
		else:
			while portStart >= portEnd:
				portList.append(portStart)
				portStart -= 1
	else:
		portList = []
		portList.append(options.ports)

	for i in portList:
		if int(i) < 0 or int(i) > 65535:
			print "One or more ports is out of range"
			parser.print_help()
			sys.exit(2)


	#Add in the scans chosen
	if options.tcp:
		scans.append("tcp")
	if options.udp:
		scans.append("udp")
	if options.icmp:
		scans.append("icmp")
	if options.traceroute:
		scans.append("traceroute")

	if not scans:
		print "Choose a scan type"
		parser.print_help()
		sys.exit(2)

	ipStart = 0
	ipEnd = 0


	# help here from: https://gist.github.com/nboubakr/4344773

	#For subnet mask using slash notation
	if "/" in ip_raw:

		(addrString, cidrString) = ip_raw.split('/')

		# Split address into octets and turn CIDR into int
		addr = addrString.split('.')
		cidr = int(cidrString)

		#Make sure slash notation is valid
		if cidr < 0 or cidr > 31:
			print "Slash notation is out of range"
			parser.print_help()
			sys.exit(2)

		# Initialize the netmask and calculate based on CIDR mask
		mask = [0, 0, 0, 0]
		for i in range(cidr):
			mask[i/8] = mask[i/8] + (1 << (7 - i % 8))

		# Initialize net and binary and netmask with addr to get network
		net = []
		for i in range(4):
			net.append(int(addr[i]) & mask[i])

		# Duplicate net into broad array, gather host bits, and generate broadcast
		broad = list(net)
		brange = 32 - cidr
		for i in range(brange):
			broad[3 - i/8] = broad[3 - i/8] + (1 << (i % 8))

		# Print information, mapping integer lists to strings for easy printing
		# print "Address:   " , addrString
		# print "Netmask:   " , ".".join(map(str, mask))
		# print "Network:   " , ".".join(map(str, net))
		# print "Broadcast: " , ".".join(map(str, broad))

		netAddress = ".".join(map(str, net))
		broadAddress = ".".join(map(str, broad))

		seperated = addrString.split(".")
		split_range = seperated[3].split("-")

		ipStart = int(netAddress.split(".")[3])
		ipEnd = int(broadAddress.split(".")[3])

		while ipStart <= ipEnd:
			ips.append(seperated[0] + "." + seperated[1] + "." + seperated[2] + "." + str(ipStart))
			ipStart += 1

	elif "-" in ip_raw:
		seperated = ip_raw.split(".")
		split_range = seperated[3].split("-")

		ipStart = int(split_range[0])
		ipEnd = int(split_range[1])

		#Make sure they are within the valid ranges...
		if ipStart < 0 or ipStart > 255 or ipEnd < 0 or ipEnd > 255:
			print "IP address out of range"
			parser.print_help()
			sys.exit(2)

		while ipStart <= ipEnd:
			ips.append(seperated[0] + "." + seperated[1] + "." + seperated[2] + "." + str(ipStart))
			ipStart += 1

	else:
		ips.append(ip_raw)

	#Now to the scanning
	conf.verb = 0

	for i in scans:
		print ""
		print "=======Now Performing " + i.upper() + " Scan========"

		if i == "tcp":

			if not options.ports:
				print "Must select a port or ports to scan"
				parser.print_help()
				sys.exit(2)

			for x in ips:

				ping = IP(dst=x)/ICMP()
				resp = sr1(ping, timeout=10)
				if resp == None:
					print "\n[!] Could not resolve" + x
				else:
					print "------------------"
					print "Host is up. Beginning Scan on " + x
					print ""

					for port in portList:
						src_port = RandShort()
						dst_port = int(port)
						scan = sr1(IP(dst=x)/TCP(sport=src_port, dport=dst_port,flags="S"), timeout=2)
						if scan is None:
							print i + "/" + str(port) + "   Closed"
						elif(scan.haslayer(TCP)):
							if(scan.getlayer(TCP).flags == 0x12):
								print i + "/" + str(port) + "   Open"
							elif(scan.getlayer(TCP).flags == 0x14):
								print i + "/" + str(port) + "   Closed"
						else:
							print i + "/" + str(port) + "   Unknown"

		#Help with this one from: https://github.com/interference-security/Multiport/blob/master/multiport.py
		elif i == "udp":
			for x in ips:

				ping = IP(dst=x)/ICMP()
				resp = sr1(ping, timeout=10)
				if resp == None:
					print "\n[!] Could not resolve" + x
				else:
					print "------------------"
					print "Host is up. Beginning Scan on " + x

					for port in portList:
						src_port = RandShort()
						dst_port = int(port)
						scan = sr1(IP(dst=x)/UDP(sport=src_port, dport=dst_port), timeout=2)

						if (str(type(scan)) == "<type 'NoneType'>"):
							print i + "/" + str(port) + "   Open|Filtered"

						elif (scan.haslayer(UDP)):
							print i + "/" + str(port) + "   Open"

						elif (scan.haslayer(ICMP)):
							if(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code)==3):
								print i + "/" + str(port) + "   Closed"
							elif(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code) in [1,2,9,10,13]):
								print i + "/" + str(port) + "   Filtered"
						else:
							print i + "/" + str(port) + "   Closed"


		elif i == "icmp":
			for x in ips:

				ping = IP(dst=x)/ICMP()
				resp = sr1(ping, timeout=10)
				if resp == None:
					print "\n[!] Could not resolve " + x
				else:
					print "\n[*] " + str(x) + " is up!"

		elif i == "traceroute":
			for x in ips:
				for j in range(1,28):
					packet = IP(dst=x, ttl=j) / UDP(dport=33434)
					scan = sr1(packet, verbose=0)
					# scan = sr1(IP(dst=x, ttl=j)/UDP(dport=33434), timeout=2)

					if scan == None:
						print "\n[!] Trace Ended"
						break
					elif scan.type == 3:
						print "End of Trace"
					else:
						print "Hop " + str(j) + ": ", scan.src


if __name__ == "__main__":
	main()