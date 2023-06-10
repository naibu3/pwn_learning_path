---
autor: naibu3
---

# pwntools

## ¿Qué es?

Es una librería muy útil para python que nos proporciona una gran cantidad de herramientas para scripting orientado a CTFs y hacking.

## Instalación

Seguir los pasos del [github](https://github.com/Gallopsled/pwntools) oficial.

## Uso

Pwntools se compone de una gran cantidad de funcionalidades. A continuación enumero las que más utilizo:


### Cyclic

Con `cyclic` podemos generar por terminal una cadena de carácteres que nos será muy útil para calcular *offsets* a la hora de realizar [buffer overflows](00_Simple_Buffer_Overflow):

```bash
cyclic 100
```
```cyclic
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
```

Para calcular el *offset*, si por ejemplo un registro se sobrescribió con `haaa`:

```bash
cyclic -l haaa
```
```cyclic
28
```
