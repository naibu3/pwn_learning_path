#include <stdio.h>
#include <string.h>

#define NUM_PREGUNTAS 5

// Estructura para almacenar preguntas y respuestas
struct Pregunta {
    char pregunta[256];
    char opciones[4][100];
    char respuesta_correcta;
};

void hacer_preguntas(struct Pregunta preguntas[]);

int main() {

	// Desactivar el buffering de salida estándar (stdout)
    setbuf(stdout, NULL);

    // Desactivar el buffering de entrada estándar (stdin)
    setbuf(stdin, NULL);

    // Definir las preguntas y respuestas correctas
    struct Pregunta preguntas[NUM_PREGUNTAS] = {
        {"¿Qué arquitectura tiene este binario?",
         {"a) MIPS", "b) x86", "c) x86_64", "d) ARM"},
         'b'},

        {"¿Qué protección está deshabilitada?",
         {"a) PIE", "b) Canary", "c) CTF", "d) NX"},
         'd'},

        {"¿Cual es la dirección de system?",
         {"a) 0x00000000", "b) 0x52FE6A31", "c) 0xFFFFFFFF", "d) 0x555543FE"},
         'b'},

        {"¿Con qué herramienta podemos descompilar el binario?",
         {"a) Ghidra", "b) Nmap", "c) Python3", "d) VisualStudio"},
         'a'},

        {"¿Cuál es la contraseña super secreta?",
         {"a) AtunBl4nco", "b) Password123", "c) Banana123", "d) p455w0rd"},
         'c'}
    };

    hacer_preguntas(preguntas);

    return 0;
}

void hacer_preguntas(struct Pregunta preguntas[]) {
    char respuesta;
    int correctas = 0;

    for (int i = 0; i < NUM_PREGUNTAS; i++) {
        printf("\n%s\n", preguntas[i].pregunta);
        for (int j = 0; j < 4; j++) {
            printf("%s\n", preguntas[i].opciones[j]);
        }

        printf("Tu respuesta: ");
        scanf(" %c", &respuesta);

        // Convertir la respuesta a minúscula para evitar errores por mayúsculas/minúsculas
        if (respuesta == preguntas[i].respuesta_correcta) {
            correctas++;
        }
    }

    if (correctas == NUM_PREGUNTAS) {
        printf("\n¡Enhorabuena! Has respondido correctamente a todas las preguntas. Tu flag es: pwn{3st0_e5_uN4_fl4G_p3r0_n0_eS_pWn}\n");
    } else {
        printf("\nHas respondido correctamente a %d de %d preguntas.\n", correctas, NUM_PREGUNTAS);
    }
}
