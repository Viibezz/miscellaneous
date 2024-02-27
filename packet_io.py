"""
I wrote a similar script many years ago for a school project and wanted to 
redo the project to analyze my WiFi signal at different spots.

packet_io.py
The script utilizes IPv4 & IPv6 binding a (TCP/UDP) socket to a specified 
IP and port, to send & receive packets using the Socket library.
The size of the socket buffer can be set to optimize packet handling. 
The script tracks the throughput over time in a hashmap, to draw an 
analysis diagram for analyzing a WiFi network's throughput at different 
distances.

The throughput is calculated by dividing the size of each packet 
(in kilobytes) by the elapsed time taken for the packet to be transmitted. 
"""

import socket
import time


class PacketHandler:
    def __init__(self, protocol, ip, port, packet_size, choice):
        self.protocol = protocol
        self.ip = ip
        self.port = port
        self.packet_size = packet_size
        self.choice = choice

        # Create a socket
        self.socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM,
        )
        # Bind and listen if we are receiving and not sending
        if choice == "2":
            self.socket.bind((ip, port))

    # This function sends packets
    def send_packet_client(self, packet):
        self.socket.connect((self.ip, self.port))
        self.socket.sendall(bytes(packet, "utf-8"))
        data = self.socket.recv(self.packet_size)
        print("The Server Received: ", repr(data))

    # This function receives packets
    def receive_packet_server(self):
        self.socket.connect((self.ip, self.port))
        self.socket.listen(2)
        conn, addr = self.socket.accept()
        with conn:
            while True:
                data = conn.recv(self.packet_size)
                if not data:
                    break
                conn.sendall(data)
                print(f"Connected by {addr} - Data received: {data}")

    # This function displays throughput
    def display_throughput(self):
        pass


if __name__ == "__main__":
    choice = input("1.Send Packets\n2.Receive Packets\n")
    while choice != "1" and choice != "2":
        choice = input("1.Send Packets\n2.Receive Packets\n")

    # protocol, ip, port, packet_size = input("TCP or UDP"), input('IP'), input('Port'), input('Packet Size')

    protocol, ip, port, packet_size = "TCP", None, 1337, 1024
    packet_handler = PacketHandler(protocol.lower(), ip, port, packet_size, choice)

    if choice == "1":
        packet_handler.send_packet_client("This is a packet")
    elif choice == "2":
        received_packets = packet_handler.receive_packet_server()
        print("Received packets: ", received_packets)
