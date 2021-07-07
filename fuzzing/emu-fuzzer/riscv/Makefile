# We need to be able to overwrite this with our cross-compiler
CC ?= gcc

VULN_DIR = ../../../vulnerable_programs

all: minimal hello_world shift echo-argv text-file-parser

minimal: minimal.c
	${CC} minimal.c -o minimal

hello_world: hello_world.c
	${CC} hello_world.c -o hello_world

echo-argv: echo-argv.c
	${CC} echo-argv.c -o echo-argv

shift: shift.c
	${CC} shift.c -o shift

text-file-parser: ${VULN_DIR}/text_file_parser/vuln.c
	${CC} ${VULN_DIR}/text_file_parser/vuln.c -o text-file-parser

.PHONY: clean
clean:
	rm -f minimal
	rm -f hello_world
	rm -f shift
	rm -f echo-argv
	rm -f text-file-parser
