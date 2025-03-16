# 
# Columbia University - CSEE 4119 Computer Networks
# Assignment 2 - Mini Reliable Transport Protocol
#
# mrt_client.py - defining client APIs of the mini reliable transport protocol
#

import socket
import time
import struct
import threading


SYN = 0x1
ACK = 0x2
FIN = 0x4

STATE_UNESTABLISHED = 0
STATE_SYN_SENT = 1
STATE_ESTABLISHED = 2

TIME_WINDOW = 1

class Timer:
    def __init__(self):
        self.start_time = time.time()

    def reset(self):
        self.start_time = time.time()

    def check_timeout(self):
        return time.time() - self.start_time > TIME_WINDOW

########## PLAN:
# 1. sent data -> expect ack: (if not received, wait for timeout and resend)
# data loss (lack of ack), detect(expect) + timer

class Client:
    def __init__(self):
        self.state = STATE_UNESTABLISHED
        self.client_socket = None
        self.server_addr = None
        self.segment_size = 0
        self.seq = 0 # also treated as the next_seq_num
        self.ack_num = 0
        self.running = True

        # Go-Back-N variables
        self.send_base = 1
        # self.next_seq_num = 1
        self.window_size = 5
        self.window_segments = {}
        self.fast_retransmit_dict = {}

        self.rcv_thread = None

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
        self.client_socket.setblocking(False)
        print(f"[Client] Initialized on port {src_port}, non-blocking socket set.")


    def rcv_and_sgmnt_handler(self):
        """
        Single child thread that:
          2) Non-blocking receives inbound segments (e.g., ACKs, FIN, etc.) and processes them.

         further develop, add:
         - Retransmission timers
         - Sliding window
         - Checksum and corruption handling
         - Flow control
        """
        while self.running:
            # 1) Send any queued segments, 这里我们可能需要把send_segments()拿到外面,
            # 这个thread只负责(including checking ACK nums of received segments, retransmitting segments when necessary, etc.)
            # 这个thread应该只是负责在ack没收到的时候timeout重发, 我们要在parent thread进行segment的发送, 但是需要对于发送的segment
            # 进行buffer 并且我们这里的thread可以访问到, 以便于在ack没收到并且timeout的时候进行重发,

            self.receive_acks()

            # check timeout
            self.monitor_timeout()

            # Avoid spinning too fast
            # time.sleep(0.001)

    def monitor_timeout(self):
        """
        Monitor the timeout of the segments in the window
        """
        if len(self.window_segments) == 0:
            return
        if self.window_segments[self.send_base][1].check_timeout():
            print(f"Timeout for seq={self.send_base}, current time: {time.time()}, retransmitting segment....")
            # retransmit the segment
            self.client_socket.sendto(self.window_segments[self.send_base][0].construct_raw_data(), self.server_addr)
            self.window_segments[self.send_base][1].reset()

    def receive_acks(self):
        """
        Tries to receive one inbound packet in non-blocking mode.
        If there's no data, an exception occurs, and we ignore it.
        """
        try:
            raw_data, addr = self.client_socket.recvfrom(65535)
        except BlockingIOError:
            return
        except OSError:
            return

        seg = Segment.extract_header(raw_data)
        if not seg.type & ACK:
            print("not an ACK segment")
            return

        if seg.ack >= self.send_base:
            # later we can make it accept the acks for the segments in the window, to handle out of order acks但是不影响我们文件的发送
            # 需要在这里进行缓存下那些window中但不是send_base的segment的acks, 然后在这里进行ack的处理

            print(f"[Client Thread] Received ACK for seg.ack={seg.ack}, self.send_base={self.send_base}, we move the window by { 1 + seg.ack - self.send_base}.")
            gap = 1 + seg.ack - self.send_base
            self.send_base += gap  # move the window
            for i in range(self.send_base - gap, self.send_base):
                self.window_segments.pop(i, None)
                self.fast_retransmit_dict.pop(i, None)
        else:
            print(f"[Client Thread] Received ACK != self.send_base: ack {seg.ack} self.send_base={self.send_base}, possible detecting out of order packet / lost packet on the receiver side, ignoring for now(需要改变later)")
            count = self.fast_retransmit_dict.get(seg.ack, None)
            self.fast_retransmit_dict[seg.ack] = count + 1 if count is not None else 1
            if self.fast_retransmit_dict.get(seg.ack) == 2: # got 3 duplicate acks, the current send_base is the one that needs to be retransmitted
                print(f"Fast retransmitting segment with seq={seg.ack} due to 3 duplicate acks, resend self.send_base={self.send_base}")
                self.client_socket.sendto(self.window_segments[self.send_base][0].construct_raw_data(), self.server_addr)
                self.window_segments[self.send_base][1].reset()

        print(
            f"[Client Thread] Received segment: seq={seg.seq}, ack={seg.ack}, type={seg.type}")


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


    def construct_segment_and_send(self, src_port, dst_port, seq, ack, type, window, payload):
        """
        Construct a segment and send it to the server
        """
        seg = Segment(src_port, dst_port, seq, ack, type, window, payload)
        self.client_socket.sendto(seg.construct_raw_data(), self.server_addr)
        return seg

    def connect(self):
        """
        connect to the server
        blocking until the connection is established

        it should support protection against segment loss/corruption/reordering
        """

        # Temporarily set socket to blocking for handshake
        self.client_socket.setblocking(True)

        self.seq = 1

        syn_seg = self.construct_segment_and_send(self.client_socket.getsockname()[1], self.server_addr[1], self.seq, 0, SYN, 4096, b"")
        print(f"[Client] Sent SYN (seq={self.seq}) to server.")

        # Wait for SYN+ACK from the server (blocking)
        self.client_socket.settimeout(1)
        while True:
            try:
                raw_data, addr = self.client_socket.recvfrom(65535)
            except socket.timeout:
                print("[Client] resend syn_seg.")
                self.client_socket.sendto(syn_seg.construct_raw_data(), self.server_addr)
                continue

            seg1 = Segment.extract_header(raw_data)
            if (seg1.type & SYN) and (seg1.type & ACK):
                if seg1.ack == self.seq + 1:
                    print(f"[Client] Received SYN+ACK (seq={seg1.seq}, ack={seg1.ack})")
                    break
                else:
                    print(f"[Client] Received SYN+ACK with unexpected ack={seg1.ack}, expecting {self.seq + 1}.")
            else:
                print("[Client] Received unexpected segment during handshake, ignoring.")

        # Send final ACK
        self.seq += 1
        self.ack_num = seg1.seq + 1
        final_ack = self.construct_segment_and_send(self.client_socket.getsockname()[1], self.server_addr[1], self.seq, self.ack_num, ACK, 4096, b"")
        self.window_segments[self.seq] = (final_ack, Timer())
        print(f"[Client] Sent final ACK (seq={self.seq}, ack={self.ack_num}).")
        self.state = STATE_ESTABLISHED

        # Revert socket to non-blocking mode for normal operation
        self.client_socket.setblocking(False)
        self.client_socket.settimeout(0.5)

        #  if the Final Ack is lost and the server resend the SYN+ACK, we need to check here: wait for the ack confirmation of the final ACK from server
        while True:
            try:
                raw_data, addr = self.client_socket.recvfrom(65535)
                seg1 = Segment.extract_header(raw_data)
                if (seg1.type & SYN) and (seg1.type & ACK): # request from the server due to possible lost final ACK
                    print("resend final ACK")
                    self.client_socket.sendto(final_ack.construct_raw_data(), self.server_addr)
                elif seg1.type & ACK: # received the final ACK confirmation from server
                    print("received final ACK from server")
                    break
            except socket.timeout:  # the final ACK confirmation from server is lost, resend the final ACK
                self.client_socket.sendto(final_ack.construct_raw_data(), self.server_addr)
                print("timeout, resend final ACK")

        print("[Client] Handshake complete. Socket set to non-blocking mode, state=ESTABLISHED.")
        # Spawn the rcv_and_sgmnt_handler in a daemon thread
        self.rcv_thread = threading.Thread(target=self.rcv_and_sgmnt_handler, daemon=True)
        self.rcv_thread.start()

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

        bytes_sent = 0
        chunk_size =  self.segment_size - Segment.HEADER_SIZE
        self.seq = 1  # reset seq number
        data_sent = 0
        while data_sent < len(data):
            if self.seq < self.send_base + self.window_size:
                print("self.seq: ", self.seq )

                chunk = data[data_sent:data_sent + chunk_size]
                seg = self.construct_segment_and_send(self.client_socket.getsockname()[1], self.server_addr[1], self.seq, self.ack_num, 0, 4096, chunk)
                self.window_segments[self.seq] = (seg, Timer()) # store the segment in the window for waiting the ack or potential retransmission
                data_sent += len(chunk)
                bytes_sent += len(chunk)
                self.seq += 1


        end_seg = Segment(self.client_socket.getsockname()[1], self.server_addr[1], self.seq,self.ack_num, FIN, 4096, b"")
        end_data = end_seg.construct_raw_data()
        self.client_socket.sendto(end_data, self.server_addr)
        # self.window_segments[self.seq] = (end_data, Timer())
        print(f"[Client] sent final FIN seg.")

        while len(self.window_segments) > 0:
            time.sleep(0.15)
            print(f"[Client] Waiting for all segments to be acknowledged...")

        return bytes_sent

    def close(self):
        """
        request to close the connection with the server
        blocking until the connection is closed
        """
        time.sleep(4)
        self.running = False
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
        checksum = Segment.simple_hash(temp_header + payload)
        if checksum != cksum:
            print(f"Warning: Checksum mismatch (expected {cksum}, got {checksum})")

        seg = cls(src_port, dst_port, seq, ack, type, window, payload)
        seg.cksum = cksum
        return seg