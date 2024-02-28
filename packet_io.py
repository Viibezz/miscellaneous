"""
I wrote a similar script many years ago for a school project and wanted to 
redo the project to analyze my WiFi signal at different spots.

packet_io.py
The script utilizes IPv4 to bind a (TCP/UDP) socket to a specified  
IP and port, to send & receive packets using the Socket library.
The size of the socket buffer can be set to optimize packet handling. 
The script tracks the throughput over time in a set, to draw an 
analysis diagram for analyzing a WiFi network's throughput at different 
distances.

The throughput is calculated by dividing the size of each packet 
(in kilobytes) by the elapsed time taken for the packet to be transmitted. 
"""

import socket
import time
import statistics


class PacketHandler:

    def __init__(self, protocol, ip, port, packet_size, send_or_receive):
        self.protocol = protocol
        self.ip = ip
        self.port = port
        self.packet_size = packet_size
        self.send_or_receive = send_or_receive
        self.connected = False
        self.throughputs = set()

        # Create a socket
        self.socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM,
        )
        # Bind and listen if we are receiving and not sending
        if send_or_receive == "2":
            self.socket.bind((ip, port))

    # This function sends packets
    def send_packet_client(self, packet):
        try:
            start_time = time.time()
            if not self.connected:
                self.socket.connect((self.ip, self.port))
                self.connected = True
            self.socket.sendall(bytes(packet, "utf-8"))
            end_time = time.time()
            print(self.display_throughput("uplink", end_time - start_time))
            data = self.socket.recv(self.packet_size)
            print("The server echoed back: ", repr(data))
        except Exception as e:
            print("Error: ", e)

    # This function receives packets
    def receive_packet_server(self):
        try:
            print(f"Server listening on {self.ip}/{self.protocol}:{self.port}...")
            # Listen to TCP/IP with max 2 connections
            if self.protocol == "tcp":
                self.socket.listen(2)
                while True:
                    start_time = time.time()
                    conn, addr = self.socket.accept()
                    with conn:
                        while True:
                            data = conn.recv(self.packet_size)
                            end_time = time.time()
                            if not data:
                                print(f"Connection closed by {addr}")
                                return
                            print(f"Connected by TCP/{addr} - Data received: {data}")
                            conn.sendall(data)
                            print("Echoed data back to client.")
                            print(
                                self.display_throughput(
                                    "downlink", end_time - start_time
                                )
                            )
            # UDP is connectionless, no need to listen
            else:
                while True:
                    start_time = time.time()
                    data, addr = self.socket.recvfrom(self.packet_size)
                    end_time = time.time()
                    print(f"From {addr} - Data received: {data}")
                    print(self.display_throughput("downlink", end_time - start_time))
        except Exception as e:
            print("Error: ", e)

    # This function displays (down/up)link throughput
    def display_throughput(self, direction, elapsed_time):
        tp = "{:.3f}".format((self.packet_size * 0.001) / elapsed_time)
        self.throughputs.add(float(tp))
        return f"Packet {direction} throughput: {tp} kilobytes per second"


if __name__ == "__main__":
    # '1' = send, '2' = receive
    send_or_receive = input("1.Send Packets\n2.Receive Packets\n")
    while send_or_receive != "1" and send_or_receive != "2":
        send_or_receive = input("1.Send Packets\n2.Receive Packets\n")

    # protocol, ip, port, packet_size = input("TCP or UDP: "), input('IP: '), input('Port: '), input('Packet Size: ')

    protocol, ip, port, packet_size = "udp", "", 1337, 1024
    packet_handler = PacketHandler(
        protocol.lower(), ip, port, packet_size, send_or_receive
    )

    # send data to the server
    if send_or_receive == "1":
        new_message = True
        while new_message:
            packet_data = input("Message to send (-1 to exit): ")
            if packet_data != "-1":
                packet_handler.send_packet_client(packet_data)
            else:
                new_message = False
    # receive data
    elif send_or_receive == "2":
        received_packets = packet_handler.receive_packet_server()

    if packet_handler.throughputs:
        print(
            "Average throughput: ", statistics.mean(packet_handler.throughputs), "kbps"
        )

    print("Goodbye.")

    # 1) close the socket
    # 2) Threading?
    # 3) IPv6?
