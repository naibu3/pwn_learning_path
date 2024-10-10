all: quiz binary

quiz: quiz.c
	gcc -o $@ $^

binary: binary.c
	gcc -o $@ $^ -z execstack -m32
