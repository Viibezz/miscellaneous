'''
ARP poisoning attack and man-in-the-middle interception using the Scapy library.

1. Select a target device
2. Modify its ARP cache table to replace target device MAC with the attacker's
3. Do same step #2 for the router/gateway device ^
4. `arp -a` / Wireshark

ARP
  IPv4 designed for efficiency not security, connect to a network and make 
   an ARP Request that every device will resposnd to & identify themselves

Prevent ARP Poisoning
  Use VPN to tunnel encrypted traffic
  Define static ARP entry for devices/IP addresses  
  IPv6 comes with Neighboring Discovery Protocol (NDP) to verify host
'''

import scapy
import time


if __name__ == "__main__":
  # Victim and gateway information
  victim_ip = "192.168.1.7"
  gateway_ip = "192.168.1.1"
