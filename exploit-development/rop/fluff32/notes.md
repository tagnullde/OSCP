# print functions
1.0 objdump -M intel -d / -D fluff32

        * 08048670 <questionableGadgets>
        * 0804864c <usefulFunction>
            - 804865a: call   8048430 <system@plt>

# print sections
2.0 objdump -M intel -h fluff32

        * .data     0804a028 (8 Bytes)
        * .dynamic  08049f14 (e8 Bytes)

2.1 rabin2 -S fluff32

        * 25 0x00001028     8 0x0804a028     8 -rw- .data
        * 22 0x00000f14   232 0x08049f14   232 -rw- .dynamic

# find strings
3.0 rabin2 -z fluff32


