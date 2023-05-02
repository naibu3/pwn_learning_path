---
autor: naibu3
---

# gdb

## ¿Qué es?

*GDB* no necesita introducción, es uno de los depuradores más usados actualmente y viene instalado con la mayor parte de distros de linux.

En concreto lo utilizaremos con tres de sus plugins para *pwn*: [[pwndbg]], [[GEF]] y [[peda]]. Al menos es recomendable utilizar la primera.

## Instalación

Si no tenemos *gdb* instalado por defecto, podemos instalarlo con:

```bash
sudo apt install gdb
```

Para la instalación de los plugins seguir las instrucciones de esta [página](https://infosecwriteups.com/pwndbg-gef-peda-one-for-all-and-all-for-one-714d71bf36b8).


# gdb-pwndbg

Es uno de los plugins que utilizaremos.

## Uso

Para iniciar el programa (si lo hemos instalado según el artículo), debemos escribir:

```bash
gdb-pwndbg <binario>
```

O bien llamarlo sin argumentos y una vez dentro abrir el archivo con:

```gdb
file <nombre>
```

### Comandos

- `info`
	- `info functions` - Muestra las funciones del programa.
	- `info stack` - Muestra el contenido del *stack*.
- `disassemble <function>` - Desensambla una función para mostrar el código en *assembly*.
- `break <function>` - Establece un *breakpoint* en dicha función.
- `delete breakpoints` - Elimina todos los *breakpoints*.
- `run` - Ejecuta el programa. 
- `c` - Continua la ejecución.
- `x $registro` - Muestra el contenido del registro.
- `p *registro` - Muestra el contenido del registro al que apunta el registro especificado.
- `set $registro valor` - Establece el valor de un registro.
- `quit` - Salir del programa.