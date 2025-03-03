# 
# Columbia University - CSEE 4119 Computer Networks
# Assignment 2 - Mini Reliable Transport Protocol
#
# mrt_client.py - defining client APIs of the mini reliable transport protocol
#

import socket # for UDP connection
import struct

SYN = 0x1
ACK = 0x2
FIN = 0x4

STATE_UNESTABLISHED = 0
STATE_SYN_SENT = 1
STATE_ESTABLISHED = 2

class Client:
    def __init__(self):
        self.state = STATE_UNESTABLISHED
        self.client_socket = None
        self.server_addr = None
        self.seq = 0
        self.ack_num = 0

    def init(self, src_port, dst_addr, dst_port, segment_size):
        """
        initialize the client and create the client UDP channel

        arguments:
        src_port -- the port the client is using to send segments
        dst_addr -- the address of the server/network simulator
        dst_port -- the port of the server/network simulator
        segment_size -- the maximum size of a segment (including the header)
        """
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client_socket.bind(('', src_port))
        self.server_addr = (dst_addr, dst_port)
        self.segment_size = segment_size
        print(f"[Client] Initialized on port {src_port}")


        ############################################################################################################

        # client-side:
        # 1) Send SYN to the server
          # seq = 1, ack = 0, type = SYN
        # 2) Wait for SYN+ACK from the server (check server ack == client seq + 1)) -> receive SYN+ACK -> send final ACK
            # seq = 2, ack = 2, type = ACK


        # server-side:
        # 1) Wait for SYN from the client -> receive SYN and then send SYN+ACK
          # seq = 1, ack = 2(seq from the client + 1), type = SYN+ACK
        # 2) Wait for final ACK from the client -> receive ACK
            # seq = 2, ack = 2, type = ACK

        ############################################################################################################

    def connect(self):
        """
        connect to the server
        blocking until the connection is established

        it should support protection against segment loss/corruption/reordering
        """
        self.seq = 1
        syn_seg = Segment(
            src_port=self.client_socket.getsockname()[1],
            dst_port=self.server_addr[1],
            seq=self.seq,
            ack=0,
            type=SYN,
            window=4096,
            payload=b""
        )
        self.client_socket.sendto(syn_seg.construct_raw_data(), self.server_addr)
        print(f"Sent SYN (seq={self.seq}), ack=0,  to server.")

        # 2) Wait for SYN+ACK from the server
        while True:
            data_bi, addr = self.client_socket.recvfrom(65535)
            print(f"[Client] <-- Received SYN+ACK")
            seg1 = Segment.extract_header(data_bi)
            if addr != self.server_addr:
                print(f"[Client] Ignoring packet from unknown addr: {addr}")
                continue

            # Check if this is SYN+ACK
            if (seg1.type & SYN) and (seg1.type & ACK):
                # Check if this ACKs our SYNseg1
                if seg1.ack == self.seq + 1:
                    print(f"[Client] <-- Received SYN+ACK(seq={seg1.seq}, ack={seg1.ack})")
                    # 3) Send final ACK
                    self.seq += 1
                    self.ack_num = seg1.seq + 1
                    seg2 = Segment(
                        src_port=self.client_socket.getsockname()[1],
                        dst_port=self.server_addr[1],
                        seq=self.seq,
                        ack=self.ack_num,
                        type=ACK,
                        window=4096,
                        payload=b""
                    )
                    self.client_socket.sendto(seg2.construct_raw_data(), self.server_addr)
                    print(f"[Client] --> Sent final ACK(seq={self.seq}, ack={self.ack_num})")
                    self.state = STATE_ESTABLISHED
                    print("[Client] State = ESTABLISHED")
                    break
                else:
                    print(f"[Client] Received SYN+ACK but ack={seg1.ack} != {self.seq + 1}, ignoring.")
            else:
                print("[Client] Received unexpected segment (not SYN+ACK), ignoring.")


    def send(self, data):
        """
        send a chunk of data of arbitrary size to the server
        blocking until all data is sent

        it should support protection against segment loss/corruption/reordering and flow control

        arguments:
        data -- the bytes to be sent to the server
        """

        if not isinstance(data, bytes):
            data = data.encode()
        if self.state != STATE_ESTABLISHED:
            print("Connection not established.")
            return

        chunk_size =  self.segment_size - Segment.HEADER_SIZE
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            seg = Segment(self.client_socket.getsockname()[1], self.server_addr[1], self.seq, self.ack_num, 0, 4096, chunk)
            date_bi = seg.construct_raw_data()
            self.client_socket.sendto(date_bi, self.server_addr)
            self.seq += 1
            print(f"Sent segment: seq={self.seq}, payload size={len(chunk)} bytes")

        end_seg = Segment(self.client_socket.getsockname()[1], self.server_addr[1], self.seq,self.ack_num, FIN, 4096, b"")
        end_data = end_seg.construct_raw_data()
        self.client_socket.sendto(end_data, self.server_addr)
        print("Test message finished sending to server.")

    def close(self):
        """
        request to close the connection with the server
        blocking until the connection is closed
        """
        self.client_socket.close()
        print("Client socket closed.")


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