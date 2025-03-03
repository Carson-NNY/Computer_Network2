# 
# Columbia University - CSEE 4119 Computer Networks
# Assignment 2 - Mini Reliable Transport Protocol
#
# mrt_server.py - defining server APIs of the mini reliable transport protocol
#

import socket # for UDP connection
import struct

SYN = 0x1
ACK = 0x2
FIN = 0x4

STATE_UNESTABLISHED = 0
STATE_SYN_SENT = 1
STATE_ESTABLISHED = 2
STATE_LISTEN = 3
STATE_SYN_RCVD = 4

#
# Server
#
class Server:
    def __init__(self):
        self.state = STATE_UNESTABLISHED
        self.server_socket = None
        self.seq = 0
        self.ack_num = 0
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
        self.state = STATE_LISTEN
        print(f"[Server] Listening on port {src_port}, state=LISTEN")

    def accept(self):
        """
        accept a client request
        blocking until a client is accepted

        it should support protection against segment loss/corruption/reordering 

        return:
        the connection to the client 
        """
        print("[Server] Waiting for a client connection...")

        # Wait for a SYN from a client
        while True:
            raw_data, client_addr = self.server_socket.recvfrom(self.receive_buffer_size)
            seg = Segment.extract_header(raw_data)

            if (seg.type & SYN) and not (seg.type & ACK):
                print(f"[Server] <-- Received SYN (seq={seg.seq}) from {client_addr}")
                self.state = STATE_SYN_RCVD
                self.ack_num = seg.seq + 1
                self.seq = 1
                # Build and send a SYN+ACK
                synack_seg = Segment(
                    src_port=self.server_socket.getsockname()[1],
                    dst_port=seg.src_port,
                    seq=self.seq,
                    ack=self.ack_num,
                    type=(SYN | ACK),
                    window=4096,
                    payload=b""
                )
                self.server_socket.sendto(synack_seg.construct_raw_data(), client_addr)
                print(f"[Server] --> Sent SYN+ACK (seq={synack_seg.seq}, ack={synack_seg.ack}) to client")
                # Now wait for the final ACK from the same client
                while True:
                    print("Waiting for the final ACK...")
                    data_bi2, addr2 = self.server_socket.recvfrom(self.receive_buffer_size)
                    print(f"the final ACK??????????")
                    if addr2 != client_addr:
                        print(f"[Server] Ignoring packet from unknown client {addr2}")
                        continue
                    seg2 = Segment.extract_header(data_bi2)
                    # Check that it's the final ACK (and not another SYN)
                    if (seg2.type & ACK) and not (seg2.type & SYN):
                        if seg2.ack == self.seq + 1:
                            print(f"[Server] <-- Received final ACK (seq={seg2.seq}, ack={seg2.ack}) from {addr2}")
                            self.state = STATE_ESTABLISHED
                            print(f"[Server] Connection with {client_addr} is now ESTABLISHED")
                            # Build a connection object to store state for this client
                            conn = {
                                "client_addr": client_addr,
                                "buffer": bytearray(),
                                "state": self.state,
                                "server_seq": self.seq,
                                "server_ack": self.ack_num
                            }
                            return conn
                        else:
                            print(
                                f"[Server] Received ACK with unexpected ack number {seg2.ack}; expecting {self.seq + 1}")
                    else:
                        print("[Server] Received an unexpected segment during handshake; ignoring.")

            else:
                print("[Server] Received non-SYN or irrelevant segment while listening; ignoring.")

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
        self.server_socket.settimeout(20)
        data = bytearray()
        # data = bytearray(conn["buffer"])
        while len(data) < length:
            try:
                data_bi, addr = self.server_socket.recvfrom(self.receive_buffer_size)
                # send ack
                ack_seg = Segment(
                    src_port=self.server_socket.getsockname()[1],
                    dst_port=addr[1],
                    seq=conn["server_seq"],
                    ack=conn["server_ack"],
                    type=ACK,
                    window=4096,
                    payload=b""
                )
                self.server_socket.sendto(ack_seg.construct_raw_data(), addr)
            except socket.timeout:
                print("Socket timed out – no more data received.")
                # break

            # if addr != conn["client_addr"]:
            #     print(f"Received segment from unknown client {addr}, ignoring.")
            #     continue

            try:
                print("22222")
                seg = Segment.extract_header(data_bi)
            except Exception as e:
                print(f"Error parsing segment: {e}")
                continue

            if seg.type & FIN:
                print("FIN segment received. Ending.....")
                break

            print(f"=============================Received segment: seq={seg.seq}, size={len(seg.payload)}")
            print(f"  payload: {seg.payload}")

            data.extend(seg.payload)
        self.server_socket.settimeout(None)
        return bytes(data)

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
        print(f"checksum: {checksum}, cksum: {cksum}")
        if checksum != cksum:
            print(f"Warning: Checksum mismatch (expected {cksum}, got {checksum})")

        seg = cls(src_port, dst_port, seq, ack, type, window, payload)
        seg.cksum = cksum
        return seg

