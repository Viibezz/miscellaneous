'''
ARP poisoning attack and man-in-the-middle interception using the Scapy library.
Spams target with ARP reply packets, saying that the gateway's MAC is the
attacker's. 
Spams gateway with ARP reply packets, saying that the target's MAC is the
attacker's.

1. Select a target device
2. Modify target machine's ARP cache table replacing gateway MAC with the attacker's,
    by sending an ARP reply to the target of attacker's MAC.
3. Do same step #2 on the router/gateway device, replacing target's MAC with 
    attacker's ^
4. `arp -a` / Wireshark

ARP
  IPv4 designed for efficiency not security, connect to a network and make 
   an ARP Request that every device will resposnd to & identify themselves

Prevent ARP Poisoning
  Use VPN to tunnel encrypted traffic
  Define static ARP entry for devices/IP addresses  
  IPv6 comes with Neighboring Discovery Protocol (NDP) to verify host
'''

from scapy.all import *  # create ARP packets
import time   # throttle  


if __name__ == "__main__":
  # Victim and gateway information
  victim_ip = "192.168.1.7"
  gateway_ip = "192.168.1.1"
