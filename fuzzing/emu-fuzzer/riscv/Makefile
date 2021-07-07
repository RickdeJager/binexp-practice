# We need to be able to overwrite this with our cross-compiler
CC ?= gcc

all: minimal hello_world shift echo-argv

minimal: minimal.c
	${CC} minimal.c -o minimal

hello_world: hello_world.c
	${CC} hello_world.c -o hello_world

echo-argv: echo-argv.c
	${CC} echo-argv.c -o echo-argv

shift: shift.c
	${CC} shift.c -o shift

.PHONY: clean
clean:
	rm -f minimal
	rm -f hello_world
	rm -f shift
	rm -f echo-argv
