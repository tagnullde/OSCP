#!/usr/bin/python3
import string

badchar = input("Enter Letter: ")

def encode(badchar):

    for x in string.printable:
        for y in range(16):
            if chr(ord(x) ^ y) == str(badchar):
                print(x + ' ' + str(y))

encode(badchar)
