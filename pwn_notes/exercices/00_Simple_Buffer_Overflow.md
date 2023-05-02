---
original autor: CrazyCat
coautor: naibu3
---

#bufferOverflow 

# 00 - Buffer Overflow

## ¿Qué es?



## Compilar el binario

Para este ejercicio utilizaremos el siguiente código:

```c
#include <stdio.h>
#include <string.h>

int main(void)
{
    char buffer[16];

    printf("Give me data plz: \n");
    gets(buffer);
    
    return 0;
}
```

Estará en el fichero *vuln.c*. Como es un código en C debemos compilarlo.

En primer lugar lo compilaremos con todas las medidas de seguridad a modo de prueba de concepto:

```bash
gcc -o vuln vuln.c -fstack-protector-all
```

El propio compilador nos reportará un aviso acerca de la función `gets()`:

```gcc
vuln.c:9:5: warning: implicit declaration of function ‘gets’; did you mean ‘fgets’? [-Wimplicit-function-declaration]
    9 |     gets(buffer);
      |     ^~~~
      |     fgets
```

Si ahora *checkeamos* el binario con [[checksec]]:

```bash
checksec --file vuln
```
```checksec
[*] '/home/naibu3/hack/aularedes/pwn_learning_path/ejercicios/00_Simple_Buffer_Overflow/vuln'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Vemos que están activas todas las protecciones. A lo largo de estos ejercicios las iremos activando para tratar de evadirlas, sin embargo por ahora volveremos a compilar eliminando las protecciones:

```bash
gcc -o vuln vuln.c -fno-stack-protector -z execstack -no-pie -m32
```

Con `-fno-stack-protector` eliminaremos la protección `Canary`; con `-z execstack`, la `NX`; y con `-no-pie` la última. El parámetro `-m32` es para compilar con arquitectura de 32 bits. Si volvemos a lanzar [[checksec]]:

```bash
checksec --file vuln
```
```checksec
[*] '/home/naibu3/hack/aularedes/pwn_learning_path/ejercicios/00_Simple_Buffer_Overflow/vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

Vemos que ahora el binario parece algo inseguro...


## Revisando el código

Si echamos un vistazo al código, veremos que el valor de `buffer` se está asignando mediante la función `gets()`. Si consultamos el manual:

```man
[...]
BUGS
       Never use gets().  Because it is impossible to tell without knowing the
       data  in  advance  how  many  characters  gets() will read, and because
       gets() will continue to store characters past the end of the buffer, it
       is  extremely dangerous to use.  It has been used to break computer se‐
       curity.  Use fgets() instead.
[...]
```

El propio manual nos recomienda no utilizar esta función, ya que es insegura. Nos dice que permite almacenar una cantidad indeterminada de carácteres, pudiendo sobrepasar el límite del buffer.

## Desbordando el buffer

Podemos probar a ejecutar el código e introducir muchas "*a*":

```bash
./vuln
Give me data plz: 
aaaaaaaaaaaaaaa
```

Con 15 no ocurre nada, pero si probamos con 16:

```bash
./vuln
Give me data plz: 
aaaaaaaaaaaaaaaa
[1]    29056 segmentation fault  ./vuln
```

Nos da un fallo de segmentación, es decir, `gets()` ha introducido en el buffer más carácteres de los que puede almacenar. En este caso, no es algo crítico, ya que es un programa muy básico y sin ninguna otra función además de `main()`. Sin embargo, esto podría llevar a un atacante a realizar un ataque de *buffer overflow* (*desbordamiento de buffer*), que sobreescribiera otras variabes o llamara a funciones.

### Analizando la ejecución con [[gdb]]

Vamos a ver qué está pasando realmente con [[gdb]]-[[pwndbg]]. Así que lo iniciamos con:

```bash
gdb-pwndbg vuln
```

Una vez dentro podemos tratar de ver qué funciones tenemos con:

```gdb
info functions
```
```gdb
[...]
0x08049170  frame_dummy
0x08049172  main
0x080491c0  __libc_csu_init
[...]
```

Vemos que tenemos la función `main()`, podemos tratar de ver qué ejecuta mirando el código en ensamblador. Para ello, debemos ejecutar:

```gdb
disassemble main
```
```gdb
[...]
0x08049199 <+39>:	call   0x8049040 <puts@plt>
0x0804919e <+44>:	add    esp,0x10
0x080491a1 <+47>:	sub    esp,0xc
0x080491a4 <+50>:	lea    eax,[ebp-0x18]
0x080491a7 <+53>:	push   eax
0x080491a8 <+54>:	call   0x8049030 <gets@plt>
0x080491ad <+59>:	add    esp,0x10
0x080491b0 <+62>:	mov    eax,0x0
[...]
```

Vemos que se está imprimiendo algo en la primera linea y se está leyendo con `gets()`, además vemos que se está utilizando el registro del *stack*, `eax`.

Vamos a establecer un *breakpoint* antes de que se ejecute `main` para tratar de ver el *stack*. Un *breakpoint* nos permite detener la ejecución para ver el estado de la memoria en un momento concreto. Lo establecemos con:

```gdb
break main
```

E iniciamos la ejecución con:

```gdb
run
```

Se detendrá en el *breakpoint*, y podremos ver el *stack* con:

```gdb
info stack
```
```gdb
#0  0x08049181 in main ()
#1  0xf7dd6e46 in __libc_start_main (main=0x8049172 [...]
#2  0x08049092 in _start ()
```

Ahí podemos ver el contenido del stack. Podemos ver también el contenido de los registros (en este caso `eax`) con:

```gdb
x $eax
```

O si apunta a otro registro (como es nuestro caso), el contenido de éste:

```gdb
p $eax
```

Vamos a continuar la ejecución con:

```gdb
c
```

Y trataremos de desbordar el *buffer* introduciendo muchas *a*:

```gdb
Continuing.
Give me data plz: 
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

Como antes, nos dará *fallo de segmentación* (*segmentation fault*) y nos reportará el contenido de los registros afectados:

```gdb
Program received signal SIGSEGV, Segmentation fault.
[...]
*EAX  0x0
*EBX  0x61616161 ('aaaa')
*ECX  0x61616161 ('aaaa')
*EDX  0xfbad2288
 EDI  0xf7fa0000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1e3d6c
 ESI  0xf7fa0000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1e3d6c
*EBP  0x61616161 ('aaaa')
*ESP  0x6161615d (']aaa')
*EIP  0x80491be (main+76) ◂— ret
```

Vemos que muchos registros se han sobreescrito con *aaaa*, y al final vemos una llamada `ret`. Como curiosidad, si vemos el *stack*, veremos que el puntero apunta a una dirección no válida:

```gdb
stack info
```
```gdb
Exception occurred: stack: No symbol "info" in current context. (<class 'gdb.error'>)
```


### Analizando con [[ghidra]]

Simplemente lanzaremos *ghidra* con el siguiente comando:

```bash
ghidra /path/to/binary
```