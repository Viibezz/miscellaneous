'''
ARP poisoning attack and man-in-the-middle interception using the Scapy library.
'''

import scapy
import time


if __name__ == "__main__":
  # Victim and gateway information
  victim_ip = "192.168.1.7"
  gateway_ip = "192.168.1.1"
