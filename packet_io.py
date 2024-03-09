"""
I found my old school project to analyze WiFi signal at different
distances and decided to review/expand this subject.

packet_io.py
The script utilizes IPv4 to bind a (TCP/UDP) socket to a specified  
IP and port, to send & receive packets using the Socket library.
The size of the socket buffer can be set to optimize packet handling. 
The script tracks the throughput over time in a set, to draw an 
analysis diagram for analyzing a WiFi network's throughput at different 
distances.

The throughput is calculated by converting each packet size from bytes 
to kilobytes and dividing it by the elapsed time (in seconds) of the packet  
transmission - throughput is typically measured in kilobytes per second.
When calculating the average throughput, including duplicate values would 
skew the average, potentially leading to less accurate results.
"""

import socket
import time
import statistics
import threading


class PacketHandler:

    def __init__(self, protocol, port, packet_size, ip="localhost"):
        self.protocol = protocol
        self.port = port
        self.packet_size = packet_size
        self.ip = ip
        self.connected = False  # flag: connected to a server or not
        self.throughputs = set()  # each packet's throughput

        # Create a socket
        self.socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM,
        )
        # Bind and listen for tcp server
        if self.protocol == "tcp" and ip == "localhost":
            self.socket.bind((ip, port))

    # This function sends packets
    def send_packet_client(self):
        try:
            while True:
                packet = input("Message to send (-1 to exit): ")
                if packet == "-1":
                    break

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
            print(f"Server listening on localhost/{self.protocol}:{self.port}...")
            # Listen to TCP/IP
            if self.protocol == "tcp":
                self.socket.listen(3)  # max connections
                while True:
                    self.handle_client()

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

    # Receive packet, echo it back, and display downlink
    def handle_client(self):
        start_time = time.time()
        conn, addr = self.socket.accept()
        with conn:
            while True:
                data = conn.recv(self.packet_size)
                end_time = time.time()
                if not data:
                    conn.close()  # connection socket
                    self.socket.close()  # listening socket
                    print(f"Connection closed by {addr}")
                    return
                print(f"Connected by TCP/{addr} - Data received: {data}")
                conn.sendall(data)
                print("Echoed data back to client.")  # log
                print(self.display_throughput("downlink", end_time - start_time))

    # This function displays (down/up)link throughput
    def display_throughput(self, direction, elapsed_time):
        tp = "{:.3f}".format((self.packet_size * 0.001) / elapsed_time)
        self.throughputs.add(float(tp))
        return f"Packet {direction} throughput: {tp} kilobytes per second"


if __name__ == "__main__":
    try:
        # protocol, ip, port, packet_size = input("TCP or UDP: "), input('IP: '), input('Port: '), input('Packet Size: ')

        protocol, ip, port, packet_size = "tcp", "192.168.1.18", 1337, 1024

        server_packet_handler = PacketHandler(protocol.lower(), port, packet_size)
        client_packet_handler = PacketHandler(protocol.lower(), port, packet_size, ip)

        send_thread = threading.Thread(target=client_packet_handler.send_packet_client)
        recv_thread = threading.Thread(
            target=server_packet_handler.receive_packet_server
        )

        # execute the thread's target function concurrently
        send_thread.start()
        recv_thread.start()

        # (send/recv)_thread waits until the main thread completes execution
        send_thread.join()
        recv_thread.join()

        if server_packet_handler.throughputs:
            print(
                "Average throughput: ",
                statistics.mean(server_packet_handler.throughputs),
                f"kbps\nTotal packets: {len(server_packet_handler.throughputs)}",
            )
        print("Goodbye.")
    except KeyboardInterrupt:
        if server_packet_handler.throughputs:
            print(
                "Average throughput: ",
                statistics.mean(server_packet_handler.throughputs),
                f"kbps\nTotal packets: {len(server_packet_handler.throughputs)}",
            )
        print("\nGoodbye.")
