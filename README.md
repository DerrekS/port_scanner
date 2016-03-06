# port_scanner
Simple python port scanner using scapy

Usage: test.py -a (ip address) -p (ports) [-i] [-u] [-t] [-T]

Options:
  -h, --help            show this help message and exit
  -a IP                 The host ip address you wish to scan (can also be a
                        range or subnet mask*). *Subnet mask option is
                        currently limited to /24+ only
  -p PORTS, --port=PORTS
                        The port(s) you wish to scan (single, comma separated,
                        or range).
  -t                    Performs a TCP port scan, along with any other scans
                        selected.
  -i                    Performs an ICMP port scan, along with any other scans
                        selected.
  -u                    Performs a UDP port scan, along with any other scans
                        selected.
  -T                    Performs a traceroute to the destination IP
