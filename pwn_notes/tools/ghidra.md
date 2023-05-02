---
autor: naibu3
---

# ghidra

## ¿Qué es?

Según sus creadores, *ghidra* es un *framework* para hacer *ingeniería inversa* (*SRE software reverse engineering*) a aplicaciones software. 

## Instalación

Seguir los pasos de su página oficial de [github](https://github.com/NationalSecurityAgency/ghidra). Además con este [script](https://gist.github.com/liba2k/d522b4f20632c4581af728b286028f8f) facilitaremos la tarea de abrir un binario en *ghidra*.

En el script debemos especificar la ruta de la carpeta de instalación de *ghidra*.

## Uso

Con nuestro script configurado, tan solo debemos ejecutar:

```bash
./ghidra.py /path/to/file
```