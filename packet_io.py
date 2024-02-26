'''
I wrote a similar script many years ago for a school project and wanted to 
redo the project to analyze my WiFi signal at different spots.

packet_io.py
The script utilizes IPV4 - binds a (TCP/UDP) socket to a specified IP 
and port using the Socket library, to send & receive packets.
The size of the socket buffer can be set to optimize packet handling. 
The script tracks the throughput over time in a hashmap, to draw an 
analysis diagram when analyzing a WiFi network's throughput at different 
distances.

The throughput is calculated by dividing the size of each packet 
(in kilobytes) by the elapsed time taken for the packet to be transmitted. 
'''

import socket
import time

class PacketHandler():
  def __init__(self, protocol, ip, port, packet_size, choice):
    self.protocol = protocol
    self.ip = ip
    self.port = port
    self.packet_size = packet_size
    self.choice = choice

    # Create a socket
    self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM)
    if choice == '2':
      self.sock.bind((ip,port)) # Bind and listen if we are receiving and not sending
  
  # This function sends packets
  def send_packet(self, packet):
    pass

  # This function receives packets
  def receive_packet(self):
    pass

  # This function displays throughput
  def display_throughput(self):
    pass

if __name__ == "__main__":
  choice = input('1.Send Packets\n2.Receive Packets\n')
  while choice != '1' and choice != '2':
      choice = input('1.Send Packets\n2.Receive Packets\n')

  # protocol, ip, port, packet_size = input("TCP or UDP"), input('IP'), input('Port'), input('Packet Size')

  protocol, ip, port, packet_size = 'TCP', '192.168.1.7', 1337, 1024
  packet_handler = PacketHandler(protocol.lower(), ip, port, packet_size, choice)

  if choice == '1':                  
    packet_handler.send_packet('This is a packet')
  elif choice == '2':
    received_packets = packet_handler.receive_packet()
    print('Received packets: ', received_packets)




