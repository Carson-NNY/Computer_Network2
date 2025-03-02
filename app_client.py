# 
# Columbia University - CSEE 4119 Computer Networks
# Assignment 2 - Mini Reliable Transport Protocol
#
# app_client.py: 
# 
# A simple example application client that uses the MRT APIs to make a connection to the server and send a file. 
#

import sys
from mrt_client import Client

# parse input arguments
# <client_port> <network_addr> <network_port> <segment_size>
# example: 50000 127.0.0.1 51000 1460
if __name__ == '__main__':
    client_port = int(sys.argv[1]) # the port the client is using to send segments
    server_addr = sys.argv[2] # the address of the server/network simulator
    server_port = int(sys.argv[3]) # the port of the server/network simulator
    segment_size = int(sys.argv[4]) # the maximum size of a segment (including the header)

    # initialize and connect to the server
    client = Client()
    client.init(client_port, server_addr, server_port, segment_size)
    client.connect()

    # open a file and send it to the server
    with open("data.txt", "rb") as f:
        data = f.read()
    sent = client.send(data)
    print(f">> sent {sent} bytes of data")
    
    # close the connection
    client.close()
