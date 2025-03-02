# 
# Columbia University - CSEE 4119 Computer Networks
# Assignment 2 - Mini Reliable Transport Protocol
#
# mrt_server.py - defining server APIs of the mini reliable transport protocol
#

import socket # for UDP connection
import struct
#
# Server
#
class Server:
    def init(self, src_port, receive_buffer_size):
        """
        initialize the server, create the UDP connection, and configure the receive buffer

        arguments:
        src_port -- the port the server is using to receive segments
        receive_buffer_size -- the maximum size of the receive buffer
        """
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.bind(('', src_port))
        self.receive_buffer_size = receive_buffer_size
        print(f"Server initialized. Ready to receive on port {src_port}")

    def accept(self):
        """
        accept a client request
        blocking until a client is accepted

        it should support protection against segment loss/corruption/reordering 

        return:
        the connection to the client 
        """
        print("Waiting for a client connection...")
        data_bi, client_addr = self.server_socket.recvfrom(self.receive_buffer_size)  # Blocking receive
        # data_bi, client_addr = self.server_socket.recvfrom(20)  # Blocking receive

        try:
            seg = Segment.extract_header(data_bi)
            print(f"Received Segment from {client_addr}:")
            print(f"  src_port: {seg.src_port}")
            print(f"  dst_port: {seg.dst_port}")
            print(f"  seq: {seg.seq}")
            print(f"  ack: {seg.ack}")
            print(f"  type: {seg.type}")
            print(f"  window: {seg.window}")
            print(f"  payload: {seg.payload}")
            print(f"  checksum: {seg.cksum}")
        except Exception as e:
            print(f"Error parsing segment: {e}")

        # Create a connection object for the client
        conn = {
            "client_addr": client_addr,
            "buffer": bytearray(),
        }

        return conn

    def receive(self, conn, length):
        """
        receive data from the given client
        blocking until the requested amount of data is received
        
        it should support protection against segment loss/corruption/reordering 
        the client should never overwhelm the server given the receive buffer size

        arguments:
        conn -- the connection to the client
        length -- the number of bytes to receive

        return:
        data -- the bytes received from the client, guaranteed to be in its original order
        """
        data = b""
        # while len(data) < length:
        #     segment, addr = self.server_socket.recvfrom(self.receive_buffer_size)
        #     print(f"Received {len(segment)} bytes from {addr}")
        #     if addr == conn["client_addr"]:
        #         data += segment
        self.close()
        return data

    def close(self):
        """
        close the server and the client if it is still connected
        blocking until the connection is closed
        """
        self.server_socket.close()
        print("Server socket closed.")


#   Segment Class
class Segment:
    HEADER_CONFIG = "!HHIIHHHH"
    HEADER_SIZE = struct.calcsize(HEADER_CONFIG)

    def __init__(self, src_port, dst_port, seq, ack, type, window, payload=b""):
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq = seq
        self.ack = ack
        self.type = type  # bitmask for SYN, ACK, FIN, etc.
        self.window = window
        self.payload = payload or b""
        self.payload_length = len(self.payload)
        self.cksum = 0

    @classmethod
    def simple_hash(cls, data: bytes) -> int:
        checksum = 0
        for byte in data:
            checksum = (checksum * 31 + byte) % 65536
        return checksum

    def construct_raw_data(self):
        """
        Construct the raw bytes representing this segment
        """
        header1 = struct.pack(
            self.HEADER_CONFIG,
            self.src_port,
            self.dst_port,
            self.seq,
            self.ack,
            self.type,
            self.window,
            self.payload_length,
            0
        )
        checksum = Segment.simple_hash(header1 + self.payload)
        self.cksum = checksum

        header2 = struct.pack(
            self.HEADER_CONFIG,
            self.src_port,
            self.dst_port,
            self.seq,
            self.ack,
            self.type,
            self.window,
            self.payload_length,
            checksum
        )
        return header2 + self.payload

    @classmethod
    def extract_header(cls, raw_data):
        """
        Parse raw bytes into a Segment object.
        """
        if len(raw_data) < cls.HEADER_SIZE:
            raise ValueError("raw data is corrupted")

        (src_port, dst_port, seq, ack, type, window, payload_length, cksum) = struct.unpack(
            cls.HEADER_CONFIG, raw_data[:cls.HEADER_SIZE]
        )

        if len(raw_data) < cls.HEADER_SIZE + payload_length:
            raise ValueError(" segment received is incomplete")

        payload = raw_data[cls.HEADER_SIZE:cls.HEADER_SIZE + payload_length]

        temp_header = struct.pack(
            cls.HEADER_CONFIG,
            src_port,
            dst_port,
            seq,
            ack,
            type,
            window,
            payload_length,
            0
        )
        checksum = Segment.simple_hash(temp_header + payload)
        if checksum != cksum:
            print(f"Warning: Checksum mismatch (expected {cksum}, got {checksum})")

        seg = cls(src_port, dst_port, seq, ack, type, window, payload)
        seg.cksum = cksum
        return seg

