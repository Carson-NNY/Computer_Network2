# CSEE 4119 Spring 2025, Assignment 2 Design File
## Guanhong Liu
## GitHub username: Carson-NNY


# Design Document

## 1. Message Types
### 1.1 SYN - 0x1
- Used for initiating handshake connection

### 1.2 ACK  - 0x2
- Used to acknowledge a successful reception of segments.

### 1.3 SYN-ACK  - 0x3 (SYN | ACK)
- Confirmation froms the server to establish a connection.

### 1.4 FIN - 0x4
- the type indicate that no more data will be send anymore.

### 1.5 SEG - 0x0
- Used for sending pure data.

---
## 2. Handling Segment Losses
Segment losses are managed using timeouts and duplicate ACKs. 

### 2.1 Timeout Retransmission
- we store each segment in `self.window_segments` on the client which is associated with a Timer object.
- If an ACK is not received within a predefined time (`TIME_WINDOW`), the segment is retransmitted.
- This is handled in `monitor_timeout()` where the client checks for expired timers and retransmits lost packets.
  ```python
  if self.window_segments[self.send_base][1].check_timeout():
      print(f"Timeout for seq={self.send_base}, retransmitting segment....")
      self.client_socket.sendto(self.window_segments[self.send_base][0].construct_raw_data(), self.server_addr)
      self.window_segments[self.send_base][1].reset()
  ```

### 2.2 Fast Retransmit
- If the receiver detects a missing segment, it continues to send duplicate ACKs for the highest accumulative ack.
- The client tracks these duplicate ACKs in `self.fast_retransmit_dict`.
- When three duplicate ACKs for the same sequence number are detected, the client immediately retransmits that segment.
  ```python
  if self.fast_retransmit_dict.get(seg.ack) == 3:
      print(f"Fast retransmitting segment with seq={seg.ack} due to 3 duplicate acks")
      self.client_socket.sendto(self.window_segments[self.send_base][0].construct_raw_data(), self.server_addr)
      self.window_segments[self.send_base][1].reset()
  ```

---
## 3. Handling Data Corruption
we use checksums to verify the integrity of received segments. 

### 3.1 Checksum Calculation
- Each segment includes a checksum computed using `Segment.simple_hash()`.
- Before data us sent, the sender calculate the checksum and embeds it in the segment’s header:
  ```python
  checksum = Segment.simple_hash(header1 + self.payload)
  self.cksum = checksum
  ```

### 3.2 Integrity Verification on Reception
- When a segment is received, the receiver extracts its header and calculates the checksum.
- Onl y return None if the computed checksum does not match the received checksum:
  ```python
  computed_cksum = Segment.simple_hash(temp_header + payload)
  if computed_cksum != cksum:
      print(f"Checksum mismatch! Expected {cksum}, got {computed_cksum}. Dropping this segment.")
      return None
  ```

### 3.3 Handling Corrupted Segments
- If a corrupted segment is received, the receiver ignores it and does not send an ACK.
- The sender will detect the missing ACK(via timeout) and retransmit the segment in `monitor_timeout()`.

---
## 4. Handling Out-of-Order Delivery, High Link Latency, and Data Transfer

### 4.1 Out-of-Order Delivery 
- We use a buffer to handle this: segments that arrived out of order are stored in `self.out_of_order_segments` on the server.
- When we got the missing segments, buffered out-of-order segments are delivered in order:
  ```python
  if seg.seq > self.seq:
      print(f"Received out-of-order segment: seq={seg.seq}, expected={self.seq}. Buffering segment.")
      self.out_of_order_segments[seg.seq] = (seg, addr)
  ```

### 4.2 High Link Latency 
- The protocol uses delayed acknowledgments to reduce overhead:
  ```python
  self.delayed_ack_timer = threading.Timer(0.5, self.send_delayed_ack, args=(addr, conn))
  ```
- If an expected segment does not arrive, retransmission is triggered after `TIME_WINDOW` expires.

### 4.3 Data Transfer
- we implement a Go-Back-N mechanism using `self.window_segments`.
- Received data is stored in `self.data_buffer` and processed in order:

---
## 5. flow control
- flow control is not implemented in this protocol.

---


