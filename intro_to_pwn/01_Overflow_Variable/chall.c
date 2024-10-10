#include <stdio.h>
#include <stdlib.h>

void leer_flag(const char *nombre_archivo) {
    FILE *archivo;
    char flag[100]; // Buffer para almacenar la flag (ajusta el tamaño según sea necesario)

    // Abrir el archivo en modo lectura
    archivo = fopen(nombre_archivo, "r");
    if (archivo == NULL) {
        perror("Error al abrir el archivo");
        return;
    }

    // Leer la flag desde el archivo
    if (fgets(flag, sizeof(flag), archivo) != NULL) {
        // Imprimir la flag
        printf("%s", flag);
    } else {
        printf("No se pudo leer la flag.\n");
    }

    // Cerrar el archivo
    fclose(archivo);
}

int main(){

	// Desactivar el buffering de salida estándar (stdout)
    setbuf(stdout, NULL);

    // Desactivar el buffering de entrada estándar (stdin)
    setbuf(stdin, NULL);

	printf("XXXXXXX       XXXXXXXXXXXXXX       XXXXXXXXXXXXXX       XXXXXXX\n");
	printf("X:::::X       X:::::XX:::::X       X:::::XX:::::X       X:::::X\n");
	printf("X:::::X       X:::::XX:::::X       X:::::XX:::::X       X:::::X\n");
	printf("X::::::X     X::::::XX::::::X     X::::::XX::::::X     X::::::X\n");
	printf("XXX:::::X   X:::::XXXXXX:::::X   X:::::XXXXXX:::::X   X:::::XXX\n");
	printf("   X:::::X X:::::X      X:::::X X:::::X      X:::::X X:::::X   \n");
	printf("    X:::::X:::::X        X:::::X:::::X        X:::::X:::::X    \n");
	printf("     X:::::::::X          X:::::::::X          X:::::::::X     \n");
	printf("     X:::::::::X          X:::::::::X          X:::::::::X     \n");
	printf("    X:::::X:::::X        X:::::X:::::X        X:::::X:::::X    \n");
	printf("   X:::::X X:::::X      X:::::X X:::::X      X:::::X X:::::X   \n");
	printf("XXX:::::X   X:::::XXXXXX:::::X   X:::::XXXXXX:::::X   X:::::XXX\n");
	printf("X::::::X     X::::::XX::::::X     X::::::XX::::::X     X::::::X\n");
	printf("X:::::X       X:::::XX:::::X       X:::::XX:::::X       X:::::X\n");
	printf("X:::::X       X:::::XX:::::X       X:::::XX:::::X       X:::::X\n");
	printf("XXXXXXX       XXXXXXXXXXXXXX       XXXXXXXXXXXXXX       XXXXXXX\n");

	char dni[25];
	int edad=0;
	
    printf("Este contenido es +18.\n");
    printf("Introduce tu DNI para verificar tu edad: ");
    gets(dni);

    printf("Tu edad es %i\n", edad);

    // Verificar el valor de la variable "numero"
    if (edad > 18) {

    	if (edad < 25){
    		leer_flag("flag.txt");
    	}
    	else{
    		printf("A donde vas viejales!\n");
    	}
        
    }
    else{
    	printf("A donde vas bebecito!\n");
    }

	return 0;
}
