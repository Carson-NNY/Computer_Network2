This project implements a Mini Reliable Transport (MRT) Protocol on top of UDP, featuring reliability mechanisms such as protection against segment losses via segment retransmissions, protection against segment corruption via checksums, protection against out-of-order delivery of segments, fast transmission if the latency is high, transmission of small or large amounts of data  

## steps to execute the program:

### Installation Guide:

To set up the environment for running the project, follow these installation steps.

**Prerequisites**
Having **Python 3** installed on your system.

**Required Dependencies**
### **1. Install Python Package Manager (pip)**
If `pip` is not installed, install it first.
```sh
sudo apt-get update
sudo apt install python3-pip
pip install opencv-python
sudo apt install libgl1-mesa-glx
```
### 1. Start the server
```sh
python3 app_server.py 60000 8000
```

### 2. Start the network simulator
```sh
python3 network.py 51000 127.0.0.1 50000  127.0.0.1 60000 Loss.txt  
```

### 3. Start the client
```sh
python3 app_client.py 50000 127.0.0.1 51000 400
```
## Description of Files
```
mrt_server.py   # include the server-side logic for the MRT protocol
mrt_client.py   # include the client-side logic for the MRT protocol
app_server.py   # include the server-side logic for the application layer
app_client.py   # include the client-side logic for the application layer
DESIGN.md       # Documentation on the design of the project
TESTING.md      # Documentation on the testing of the project
network.py      # Simulates network conditions
README.md       # Documentation on how to run the project
data.txt        # Data file to be sent
Loss.txt        # File containing the loss rate
```

## Assumptions
- **Transport Mechanism**: The protocol runs on UDP.
- **Ordered Delivery**: The client and server maintain sequence numbers to ensure proper order.
- **Network Conditions**: The network may introduce packet loss, corruption, and reordering.

