# We need to be able to overwrite this with our cross-compiler
CC ?= gcc

all: minimal hello_world

minimal: minimal.c
	${CC} minimal.c -o minimal

hello_world: hello_world.c
	${CC} hello_world.c -o hello_world

.PHONY: clean
clean:
	rm -f minimal
	rm -f hello_world
