# 
# Columbia University - CSEE 4119 Computer Networks
# Assignment 2 - Mini Reliable Transport Protocol
#
# mrt_server.py - defining server APIs of the mini reliable transport protocol
#

import socket # for UDP connection
import struct
import time
import threading

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
        self.seq = 0 # also serves as the next expected ack number
        self.ack_num = 0
        self.ack_lock = threading.Lock()
        self.delayed_ack_timer = None
        self.accumulated_ack = None

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

    def schedule_delayed_ack(self, addr, conn):
        with self.ack_lock:
            if self.delayed_ack_timer is None:
                # Schedule the ACK to be sent after 0.5 seconds
                self.delayed_ack_timer = threading.Timer(0.5, self.send_delayed_ack, args=(addr, conn))
                self.delayed_ack_timer.start()

    def send_delayed_ack(self, addr, conn):
        with self.ack_lock:
            if self.accumulated_ack is not None:
                # Send ACK for the highest accumulated sequence number
                self.construct_segment_and_send(
                    self.server_socket.getsockname()[1], addr[1],
                    conn["server_seq"], self.accumulated_ack,
                    ACK, 4096, b"", addr
                )
                # Reset accumulated ACK and timer
                self.accumulated_ack = None
                self.delayed_ack_timer = None


    def is_corrupted(self, seg):
        if seg is None:
            print("Received a corrupted segment, ignoring...")
            return True
        return False

    def construct_segment_and_send(self, src_port, dst_port, seq, ack, type, window, payload, addr):
        """
        Construct a segment and send it to the client
        """
        seg = Segment(src_port, dst_port, seq, ack, type, window, payload)
        self.server_socket.sendto(seg.construct_raw_data(), addr)
        return seg
    
    def check_lost_ack(self, conn, addr):
        '''
        wait for 4s to check if the client lost the server's ack for the last segment
        '''
        while True:
            self.server_socket.settimeout(4)
            try:
                data_bi, addr2 = self.server_socket.recvfrom(self.receive_buffer_size)
                seg = Segment.extract_header(data_bi)
                if self.is_corrupted(seg):
                    continue
                # resend the ack
                print("11111: test sending tjhe last ack====================")
                self.construct_segment_and_send(self.server_socket.getsockname()[1], addr[1], conn["server_seq"], seg.seq, ACK, 4096, b"", addr)
            except socket.timeout:
                print("no retransmission request after 4 seconds, ending the connection")
                return

    # 需要后期加入防止 segment loss for handshake
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
            raw_data, client_addr = self.server_socket.recvfrom(self.receive_buffer_size) # we have timer on the client so it does not need to set timeout
            seg = Segment.extract_header(raw_data)
            if self.is_corrupted(seg):
                continue

            if (seg.type & SYN) and not (seg.type & ACK):
                print(f"[Server] <-- Received SYN (seq={seg.seq}) from {client_addr}")
                self.state = STATE_SYN_RCVD
                self.ack_num = seg.seq + 1
                self.seq = 1
                # Build and send a SYN+ACK
                synack_seg = self.construct_segment_and_send(self.server_socket.getsockname()[1], seg.src_port, self.seq, self.ack_num, (SYN | ACK), 4096, b"", client_addr)
                print(f"[Server] --> Sent SYN+ACK (seq={synack_seg.seq}, ack={synack_seg.ack}) to client")

                self.server_socket.settimeout(0.5) # set timeout for the final ACK
                # Now wait for the final ACK from the  client
                while True:
                    print("Waiting for the final ACK...")
                    try:
                        data_bi2, addr2 = self.server_socket.recvfrom(self.receive_buffer_size)
                    except socket.timeout:
                        print("Waiting for the final ACK timeout, resending SYN+ACK")
                        self.server_socket.sendto(synack_seg.construct_raw_data(), client_addr)
                        continue

                    seg2 = Segment.extract_header(data_bi2)
                    if seg2 is None:
                        print("Received a corrupted segment, ignoring...")
                        continue
                    # Check that it's the final ACK (and not another SYN)
                    if (seg2.type & ACK) and not (seg2.type & SYN):
                        if seg2.ack == self.seq + 1:
                            print(f"[Server] <-- Received final ACK (seq={seg2.seq}, ack={seg2.ack}) from {addr2}")
                            self.state = STATE_ESTABLISHED
                            print(f"[Server] Connection with {client_addr} is now ESTABLISHED")
                            self.server_socket.settimeout(None)
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
                        print("resending SYN+ACK")
                        self.server_socket.sendto(synack_seg.construct_raw_data(), client_addr)

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
        data = bytearray()
        self.seq = 1
        while len(data) < length:
            data_bi, addr = self.server_socket.recvfrom(self.receive_buffer_size)

            seg = Segment.extract_header(data_bi)
            if self.is_corrupted(seg):
                continue

            # if seg.type & ACK is true,  the client lost the server's confirmation of the final ack for the handshake, resend it
            if seg.type & ACK:
                print(f"Received ACK segment with seq number {seg.seq}, resending final ack")
                self.construct_segment_and_send(self.server_socket.getsockname()[1], addr[1], conn["server_seq"], conn["server_ack"], ACK, 4096, b"", addr)
                continue

            # got in-order seg
            if seg.seq == self.seq:
                # wait 0.5s before sending the ack, take advantage of accumulated ack to avoid overhead of sending ack for every segment

                with self.ack_lock:
                    # Update the highest ACK to send
                    self.accumulated_ack = seg.seq
                # if self.accumulated_ack == 17 and test == 0:
                #     test = 1
                #     continue
                # Schedule delayed ACK if not already scheduled
                self.schedule_delayed_ack(addr, conn)
                self.seq += 1
                print(f"Received segment with expected seq number {seg.seq}, already scheduled ACK for {self.seq - 1}")
                
            else: # two cases: 1. seg.seq < self.seq when the client lost the server's ack  2. seg.seq > self.seq when the client lost the packet with those lost seq number.
                print(f"Received segment with unexpected seq number {seg.seq}; expecting {self.seq}, now re-sending ACK for the last in-order segment: ( resend the lost server's ack ///// do Fast-Transmission work, resend the ack for the highest accumulated seq number)")
                self.construct_segment_and_send(self.server_socket.getsockname()[1], addr[1], conn["server_seq"],
                                            self.seq - 1, ACK, 4096, b"", addr)
                continue

            if seg.type & FIN:
                print("FIN segment received. Ending.....")
                break
            print(f"=============================Received segment: seq={seg.seq}, size={len(seg.payload)}")

            data.extend(seg.payload)
        self.check_lost_ack(conn, addr)
        return bytes(data)

    def close(self):
        """
        close the server and the client if it is still connected
        blocking until the connection is closed
        """
        with self.ack_lock:
            if self.delayed_ack_timer is not None:
                self.delayed_ack_timer.cancel()
                self.delayed_ack_timer = None
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

        (src_port, dst_port, seq, ack, type, window, payload_length, cksum) = struct.unpack(
            cls.HEADER_CONFIG, raw_data[:cls.HEADER_SIZE]
        )

        # if len(raw_data) < cls.HEADER_SIZE + payload_length:
        #     raise ValueError(" segment received is incomplete")

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
            print(f" Checksum mismatch!  Expected {cksum}, got {checksum}. Dropping this segment.")
            return None

        seg = cls(src_port, dst_port, seq, ack, type, window, payload)
        seg.cksum = cksum
        return seg

