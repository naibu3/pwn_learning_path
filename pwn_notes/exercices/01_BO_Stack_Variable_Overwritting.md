brad---
original autor: CrazyCat
coautor: naibu3
---

#bufferOverflow 

# 01_BO_Stack_Variable_Overwritting

## ¿Qué es?

En el ejercicio anterior vimos como es posible sobreescribir registros adyacentes a una variable que actúa como buffer. Ahora, veremos como podemos aprovecharnos de esta vulnerabilidad para sobreescribir variables sensibles cercanas en memoria. Más concretamente en la zona del *stack* o *pila*, donde se guardan las variables *estáticas*.

Además trataremos de crear un script que automatice la interacción con el binario.

## Compilar el binario

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

## Análisis del binario

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

### Análisis con [[ltrace]] o [[strace]]

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

### Análisis con [[gdb]]

Vamos a ver ahora el análisis que haríamos normalmente. Para ello lanzamos [[gdb]]-[[pwndbg]]:

```bash
gdb-pwndbg login
```

Una vez dentro ejecutamos el programa con `run` y volvemos a introducir `aaaaaaaa` como contraseña (no pongas demasiadas *a* o generarás un fallo de segmentación):

```gdb

```