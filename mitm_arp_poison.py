'''
ARP poisoning attack and man-in-the-middle interception using the Scapy library.

ARP (Address Resolution Protocol) is a protocol used to map IP addresses to MAC addresses on a local network. It allows devices to discover and communicate with each other on the same network segment.

ARP poisoning/spoofing intercepts and manipulates network traffic between a target device and the gateway. By spoofing ARP messages, the attacker can trick the target device and the gateway into associating the attacker's MAC address with each other's IP addresses, effectively positioning the attacker as a "man-in-the-middle."

1. Select a target device on the network.
2. Spam ARP reply packets (op=2) to the target device, pretending to be the gateway (psrc). These forged ARP reply packets contain the attacker's MAC address (hwsrc), causing the target device to update its ARP cache table, associating the attacker's MAC address with the gateway's IP address.
3. Repeat the process for the gateway device, sending ARP reply packets to it with the target device's IP address and the attacker's MAC address, causing the gateway to update its ARP cache table accordingly.
4. Test with `arp -a` / wireshark
5. The attacker can now intercept, modify, or eavesdrop on network traffic between the target device and the gateway, potentially gaining access to sensitive information.

Preventing ARP Poisoning Attacks:

- Use a VPN to tunnel encrypted traffic, making it more difficult for attackers to intercept.
- Define static ARP entries for critical devices/IP addresses to prevent unauthorized ARP cache modifications.
- Implement network segmentation to isolate sensitive devices or subnets from potential attackers.
- Monitor network traffic for suspicious ARP activity and employ intrusion detection systems to detect and mitigate ARP spoofing attacks.
'''

from scapy.all import *  # create ARP packets
import time   # throttle  


if __name__ == "__main__":
  # Victim and gateway information
  victim_ip = "192.168.1.7"
  gateway_ip = "192.168.1.1"
