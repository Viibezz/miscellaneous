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
import logging

log = logging.getLogger(__name__)


class PacketHandler:
    """A class to handle sending and receiving packets over TCP/UDP."""

    def __init__(self, protocol, port, packet_size, ip="localhost"):
        """
        Initialize the PacketHandler.

        Parameters:
        - protocol (str): The protocol to use (either "tcp" or "udp").
        - port (int): The port number to bind/listen on.
        - packet_size (int): The size of the packets to send/receive.
        - ip (str, optional): The IP address to bind to or connect to. Defaults to "localhost".
        """
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
            self.socket.bind(("192.168.1.12", port))  # host IP

    def send_packet_client(self):
        """
        Start a thread to send packets from the client.
        """

        def input_thread():
            """
            Thread function to handle user input for sending packets.
            """
            try:
                while True:
                    packet_data = input("Message to send (-1 to exit client): ")
                    if packet_data == "-1":
                        log.debug("Client connection closed.")
                        print("Client connection closed.")
                        return
                    start_time = time.time()
                    if not self.connected:
                        self.socket.connect((self.ip, self.port))
                        self.connected = True
                    self.socket.sendall(bytes(packet_data, "utf-8"))
                    end_time = time.time()
                    data = self.socket.recv(self.packet_size)
                    log.info("The server echoed back: ", repr(data))
                    print("The server echoed back: ", repr(data))
                    log.info(self.display_throughput("uplink", end_time - start_time))
                    print(self.display_throughput("uplink", end_time - start_time))
            except Exception as e:
                log.error("Error in input_thread.", e)

        try:
            # This thread will allow user input of the packet data to send,
            # without waiting for the main thread to finish execution,
            # to allow receiving packets while user inputs message
            packet_input_thread = threading.Thread(target=input_thread)
            packet_input_thread.start()
        except Exception as e:
            log.error("Client Error: ", e)
        finally:
            # This will clean up after the packet input thread finishes execution,
            # before the main thread continues execution
            if packet_input_thread:
                packet_input_thread.join()

    def receive_packet_server(self):
        """
        Start listening for incoming packets on the server.
        """
        try:
            print(f"\nServer listening on localhost/{self.protocol}:{self.port}...")
            # server listens for TCP packets
            if self.protocol == "tcp":
                self.socket.listen(2)  # max connections
                while True:
                    self.handle_client()

            # UDP is connectionless, no need to listen
            else:
                while True:
                    start_time = time.time()
                    data, addr = self.socket.recvfrom(self.packet_size)
                    end_time = time.time()
                    log.info(f"From {addr} - Data received: {data}")
                    log.info(self.display_throughput("downlink", end_time - start_time))
        except:
            log.debug("Server connection closed.")

    # Receive TCP packet, echo it back, and display its throughput
    def handle_client(self):
        """
        Handle incoming client connections.
        """
        start_time = time.time()
        conn, addr = self.socket.accept()
        with conn:
            while True:
                data = conn.recv(self.packet_size)
                end_time = time.time()
                # close connection socket but keep listening for new connections
                if not data:
                    conn.close()  # connection socket
                    print(f"Connection closed by {addr}")
                    break
                log.info(f"\nConnected by TCP/{addr} - Data received: {data}")
                conn.sendall(data)
                log.debug(f"Echoed {data} back to client.")  # log
                log.info(self.display_throughput("downlink", end_time - start_time))
        self.socket.close()  # close listening socket after handling client

    def display_throughput(self, link, elapsed_time):
        """
        Display the throughput for a given link.

        :param link: The direction of the throughput (uplink/downlink).
        :param elapsed_time: The elapsed time for packet transmission.
        :return: A string representing the throughput.
        """
        tp = "{:.3f}".format((self.packet_size * 0.001) / elapsed_time)
        self.throughputs.add(float(tp))
        return f"Packet {link} throughput: {tp} kilobytes per second\n"


if __name__ == "__main__":
    try:
        # protocol, ip, port, packet_size = input("TCP or UDP: "), input('IP: '), input('Port: '), input('Packet Size: ')
        protocol, remote_ip, port, packet_size = "tcp", "192.168.1.25", 1337, 1024

        # Define receive/send sockets
        server_packet_handler = PacketHandler(protocol.lower(), port, packet_size)
        recv_thread = threading.Thread(
            target=server_packet_handler.receive_packet_server
        )
        client_packet_handler = PacketHandler(
            protocol.lower(), port, packet_size, remote_ip
        )
        send_thread = threading.Thread(target=client_packet_handler.send_packet_client)

        # execute the thread's target function concurrently
        recv_thread.start()
        send_thread.start()

        # main thread waits until (send/recv)_thread completes execution
        send_thread.join()
        recv_thread.join()

    except:
        # Display throughputs
        if server_packet_handler.throughputs:
            print(
                "\nAverage downlink throughput: ",
                statistics.mean(server_packet_handler.throughputs),
                f"kbps\nTotal packets: {len(server_packet_handler.throughputs)}",
            )
        if client_packet_handler.throughputs:
            print(
                "\nAverage uplink throughput: ",
                statistics.mean(client_packet_handler.throughputs),
                f"kbps\nTotal packets: {len(client_packet_handler.throughputs)}",
            )
        print("\nGoodbye.")
