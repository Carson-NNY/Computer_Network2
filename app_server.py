# 
# Columbia University - CSEE 4119 Computer Networks
# Assignment 2 - Mini Reliable Transport Protocol
#
# app_server.py: 
#
# It implements a simple application server that uses MRT APIs to receive data.
# It listens for incoming connections, accepts one client and receives 8000 bytes of data. 
# It then compares the received data with the source file.
# 

import sys
from mrt_server import Server

# parse input arguments
# <server_port> <buffer_size>
# example: 60000 4096
if __name__ == '__main__':
    listen_port = int(sys.argv[1]) # port to listen for incoming connections
    buffer_size = int(sys.argv[2]) # buffer size for receiving segments

    # listening for incoming connection
    server = Server()
    server.init(listen_port, buffer_size)

    # accept a connection from a client
    client = server.accept()
    # receive 8000 bytes data from client
    received = server.receive(client, 8000)

    # read the first 8000 bytes of the original file
    with open("data.txt", "rb") as f:
        input = f.read(8000)

    # compare the received file with the original file
    if input != received:
        print(f">> received {len(received)} bytes but not the same as input file")
    else:
        print(f">> received {len(received)} bytes successfully")

    # close the server and other un-closed clients
    server.close()
