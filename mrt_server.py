# Columbia University - CSEE 4119 Computer Networks
# Assignment 2 - Mini Reliable Transport Protocol
#
# mrt_server.py - defining server APIs of the mini reliable transport protocol
#

import socket  # for UDP connection
import struct
import time
import datetime
import threading
from collections import deque

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
        self.seq = 0  # also serves as the next expected data segment sequence number
        self.ack_num = 0
        self.ack_lock = threading.Lock()
        self.delayed_ack_timer = None
        self.accumulated_ack = None

        # server Buffers
        self.data_buffer = bytearray()  # in-order application data
        self.data_buffer_lock = threading.Lock()
        self.data_buffer_condition = threading.Condition(self.data_buffer_lock)

        self.rcv_buffer = deque() 
        self.rcv_buffer_lock = threading.Lock()
        self.rcv_buffer_condition = threading.Condition(self.rcv_buffer_lock)
     
        # out-of-order segments (key: seg.seq, value: (segment, addr))
        self.out_of_order_segments = {}

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

    def prepare_delayed_ack(self, addr, conn):
        """
        prepare a delayed ack for the received segments.

        This function sets up a timer to send an accumulative ACK after a short
        delay (0.5 seconds). It helps optimize performance by reducing the overhead
        of sending an ACK for every received segment.

        Arguments:
        addr -- the address of the client to send the ACK to
        conn -- the connection object containing sequence and acknowledgment details
        """
        with self.ack_lock:
            if self.delayed_ack_timer is None:
                self.delayed_ack_timer = threading.Timer(0.5, self.send_delayed_ack, args=(addr, conn))
                self.delayed_ack_timer.start()

    def send_delayed_ack(self, addr, conn):
        """
        Send a delayed ack for accumulated segments.

        This function transmits an ACK for the highest accumulated sequence number
        after a scheduled delay.

        Arguments:
        addr -- the address of the client to send the ACK to
        conn -- the connection object containing sequence and acknowledgment details
        """
        with self.ack_lock:
            if self.accumulated_ack is not None:
                # Send ACK for the highest accumulated sequence number
                self.construct_segment_and_send(self.server_socket.getsockname()[1], addr[1], conn["server_seq"], self.accumulated_ack,ACK, 4096, b"", addr)
                self.accumulated_ack = None
                self.delayed_ack_timer = None

    def is_corrupted(self, seg):
        """
        Check if the received segment is corrupted.

        This function verifies whether the given segment is valid. If the segment
        is None, it is considered corrupted and ignored.

        Arguments:
        seg -- the received Segment object

        Return:
        True if the segment is corrupted, False otherwise.
        """
        if seg is None:
            print("Received a corrupted segment, ignoring...")
            return True
        return False

    def construct_segment_and_send(self, src_port, dst_port, seq, ack, type, window, payload, addr):
        """
        Construct and send a segment to the client.

        This function creates a segment with the specified parameters,
        transmits it to the given client address, and logs the transmission.

        Arguments:
        src_port -- the source port of the segment
        dst_port -- the destination port of the segment
        seq -- the sequence number of the segment
        ack -- the acknowledgment number of the segment
        type -- the type of the segment (e.g., SYN, ACK, FIN)
        window -- the advertised receive window size
        payload -- the data payload of the segment
        addr -- the address of the client to send the segment to

        Return:
        seg -- the constructed Segment object
        """
        seg = Segment(src_port, dst_port, seq, ack, type, window, payload)
        self.server_socket.sendto(seg.construct_raw_data(), addr)
        self.log(src_port, seg)
        return seg

    def check_lost_ack(self, conn, addr):
        """
        Detect and handle lost ack segments.

        This function waits for up to 3 seconds to check if the client has lost
        the server's last ACK. If a retransmission request is received, it resends
        the ACK to ensure reliable communication.

        Arguments:
        conn -- the connection object containing sequence and acknowledgment details
        addr -- the address of the client

        If no retransmission request is received after 3 seconds, the function exits.
        """
        while True:
            self.server_socket.settimeout(3)
            try:
                data_bi, addr2 = self.server_socket.recvfrom(self.receive_buffer_size)
                seg = Segment.extract_header(data_bi)
                if self.is_corrupted(seg):
                    continue
                self.log(self.server_socket.getsockname()[1], seg)
                # resend the ack
                self.construct_segment_and_send(
                    self.server_socket.getsockname()[1], addr[1],
                    conn["server_seq"], seg.seq, ACK, 4096, b"", addr
                )
            except socket.timeout:
                print("no retransmission request after 4 seconds, ending the connection")
                return

    def log(self, port, seg):
        """
        Write a log entry for the given segment.

        This function records details of the transmitted or received segment in a
        log file named log_{port}.txt.

        Arguments:
        port -- the port number of the server socket
        seg -- the Segment object to be logged
        """
        cur_time = datetime.datetime.utcnow()
        time = cur_time.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        if seg.type & 0x1 and seg.type & 0x2:
            seg_type = "SYN-ACK"
        elif seg.type & 0x1:
            seg_type = "SYN"
        elif seg.type & 0x2:
            seg_type = "ACK"
        elif seg.type & 0x4:
            seg_type = "FIN"
        else:
            seg_type = "DATA" # data segment

        log_line = f"{time} {seg.src_port} {seg.dst_port} {seg.seq} {seg.ack} {seg_type} {seg.payload_length}\n"

        with open(f"log_{port}.txt", "a") as f:
            f.write(log_line)

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
            raw_data, client_addr = self.server_socket.recvfrom(self.receive_buffer_size)
            seg = Segment.extract_header(raw_data)
            if self.is_corrupted(seg):
                continue
            self.log(self.server_socket.getsockname()[1], seg)

            if (seg.type & SYN) and not (seg.type & ACK):
                print(f"[Server] <-- Received SYN (seq={seg.seq}) from {client_addr}")
                self.state = STATE_SYN_RCVD
                self.ack_num = seg.seq + 1
                self.seq = 1  # set next expected data segment seq number to 1
                # Build and send a SYN+ACK
                synack_seg = self.construct_segment_and_send(
                    self.server_socket.getsockname()[1], client_addr[1],
                    self.seq, self.ack_num, (SYN | ACK), 4096, b"", client_addr
                )
                print(f"[Server] --> Sent SYN+ACK (seq={synack_seg.seq}, ack={synack_seg.ack}) to client")

                self.server_socket.settimeout(0.5)  # set timeout for the final ACK
                # Now wait for the final ACK from the client
                while True:
                    print("Waiting for the final ACK...")
                    try:
                        data_bi2, addr2 = self.server_socket.recvfrom(self.receive_buffer_size)
                    except socket.timeout:
                        print("Waiting for the final ACK timeout, resending SYN+ACK")
                        self.server_socket.sendto(synack_seg.construct_raw_data(), client_addr)
                        continue

                    seg2 = Segment.extract_header(data_bi2)
                    if self.is_corrupted(seg2):
                        continue
                    self.log(self.server_socket.getsockname()[1], seg2)
                    # Check that it's the final ACK (and not another SYN)
                    if (seg2.type & ACK) and not (seg2.type & SYN):
                        if seg2.ack == self.seq + 1:
                            print(f"[Server] <-- Received final ACK (seq={seg2.seq}, ack={seg2.ack}) from {addr2}")
                            self.state = STATE_ESTABLISHED
                            print(f"[Server] Connection with {client_addr} is now ESTABLISHED")
                            self.server_socket.settimeout(None)
                            conn = {
                                "client_addr": client_addr,
                                "buffer": bytearray(),
                                "state": self.state,
                                "server_seq": self.seq,
                                "server_ack": self.ack_num
                            }
                            self.start_data_threads()
                            return conn
                        else:
                            print(f"[Server] Received ACK with unexpected ack number {seg2.ack}; expecting {self.seq + 1}")
                    else:
                        print("[Server] Received an unexpected segment during handshake; ignoring.")
                        print("resending SYN+ACK")
                        self.server_socket.sendto(synack_seg.construct_raw_data(), client_addr)
            else:
                print("[Server] Received non-SYN or irrelevant segment while listening; ignoring.")

    def start_data_threads(self):
        """
        Spawn two child threads:
        - rcv_handler(): receive segments from the socket into a  buffer.
        - sgmnt_handler(): process segments in a buffer.
        """
        self.rcv_thread = threading.Thread(target=self.rcv_handler, daemon=True)
        self.rcv_thread.start()
        self.sgmnt_thread = threading.Thread(target=self.sgmnt_handler, daemon=True)
        self.sgmnt_thread.start()

    def rcv_handler(self):
        """
        rcv_handler(): receive segments over the socket connection whenever they arrive 
        then put them into the receive buffer.
        """
        while self.state == STATE_ESTABLISHED:
            try:
                data_bi, addr = self.server_socket.recvfrom(self.receive_buffer_size)
            except socket.timeout:
                continue
            except OSError:
                break  # Socket closed
            seg = Segment.extract_header(data_bi)
            if self.is_corrupted(seg):
                continue
            self.log(self.server_socket.getsockname()[1], seg)
            with self.rcv_buffer_condition:
                self.rcv_buffer.append((seg, addr))
                self.rcv_buffer_condition.notify()

    def sgmnt_handler(self):
        """
        sgmnt_handler(): continually process segments in the receive buffer,
        to handle out-of-order arrivals and obtain in-order application data into the data buffer.
        """
        while self.state == STATE_ESTABLISHED:
            with self.rcv_buffer_condition:
                while not self.rcv_buffer:
                    self.rcv_buffer_condition.wait()
                seg, addr = self.rcv_buffer.popleft()

            # Process ACK segments (resend the lost final ACK confirmation during handshake)
            if seg.type & ACK:
                print(f"Received ACK segment with seq number {seg.seq}, resending final ack")
                self.construct_segment_and_send(
                    self.server_socket.getsockname()[1], addr[1],
                    0, 0, ACK, 4096, b"", addr)
                continue

            # Protection against out-of-order delivery:
            if seg.seq < self.seq:
                # Case 1: seg.seq < self.seq (lost server's ack scenario), so resend last in-order ACK.
                print(f"Received segment with seq {seg.seq} less than expected {self.seq}; resending ACK for last in-order segment")
                self.construct_segment_and_send(
                    self.server_socket.getsockname()[1], addr[1],
                    0, self.seq - 1, ACK, 4096, b"", addr)
                continue
            elif seg.seq > self.seq:
                # Case 2: seg.seq > self.seq (out-of-order arrival)
                print(f"Received out-of-order segment: seq={seg.seq}, expected={self.seq}. Buffering segment.")
                self.out_of_order_segments[seg.seq] = (seg, addr)
                continue
            else:
                # Case 3: In-order segment received (seg.seq == self.seq)
                print(f"Received in-order segment: seq={seg.seq}, delivering data.")
                with self.data_buffer_condition:
                    self.data_buffer.extend(seg.payload)
                    self.data_buffer_condition.notify_all()
                self.seq += 1
                # Check if any buffered out-of-order segments can now satisfy the in-order 
                while self.seq in self.out_of_order_segments:
                    buffered_seg, buffered_addr = self.out_of_order_segments.pop(self.seq)
                    print(f"Delivering buffered out-of-order segment: seq={buffered_seg.seq}")
                    with self.data_buffer_condition:
                        self.data_buffer.extend(buffered_seg.payload)
                        self.data_buffer_condition.notify_all()
                    self.seq += 1
                # Schedule delayed ACK for the highest in-order seq delivered
                with self.ack_lock:
                    self.accumulated_ack = self.seq - 1
                self.prepare_delayed_ack(addr, {"server_seq": 0, "server_ack": self.ack_num})

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
        while len(data) < length:
            with self.data_buffer_condition:
                while len(self.data_buffer) == 0:
                    self.data_buffer_condition.wait()
                len1 = length - len(data)
                chunk = self.data_buffer[:len1]
                data.extend(chunk)
                del self.data_buffer[:len1]
        
        # then check if the client lost the last ACK
        self.check_lost_ack(conn, conn["client_addr"])
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
        if self.server_socket:
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
        """
        Compute a simple hash-based checksum for the given data.

        This function iterates through the bytes of the input data and
        computes a checksum using a basic hashing formula.

        Arguments:
        data -- the byte sequence to compute the checksum for

        Return:
        The computed checksum value as an integer.
        """
        checksum = 0
        for byte in data:
            checksum = (checksum * 31 + byte) % 65536
        return checksum

    def construct_raw_data(self):
        """
        Construct the raw byte representation of this segment.

        This function creates a byte-encoded segment by packing its header fields
        and computing a checksum for error detection. The constructed segment
        consists of the header followed by the payload.

        Return:
        The raw bytes representing the segment, including the computed checksum.
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

        This function extracts the header fields and payload from the given raw byte
        sequence. It also verifies data integrity by computing and comparing checksums.

        Arguments:
        raw_data -- the raw byte sequence containing the segment data

        Return:
        A Segment object if the extraction is successful, with a warning if a
        checksum mismatch is detected.
        """
        if len(raw_data) < cls.HEADER_SIZE:
            return None
        (src_port, dst_port, seq, ack, type, window, payload_length, cksum) = struct.unpack(
            cls.HEADER_CONFIG, raw_data[:cls.HEADER_SIZE]
        )
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
        computed_cksum = Segment.simple_hash(temp_header + payload)
        print(f"checksum: {computed_cksum}, cksum: {cksum}")
        if computed_cksum != cksum:
            print(f" Checksum mismatch!  Expected {cksum}, got {computed_cksum}. Dropping this segment.")
            return None
        seg = cls(src_port, dst_port, seq, ack, type, window, payload)
        seg.cksum = cksum
        return seg
