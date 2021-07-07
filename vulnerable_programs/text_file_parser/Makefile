CC ?= gcc

all: vuln more_vuln

vuln: vuln.c
	${CC} -o vuln vuln.c -fno-stack-protector -no-pie -g -Wall -Wextra

more_vuln: more_vuln.c
	${CC} -o more_vuln more_vuln.c -fno-stack-protector -no-pie -g -Wall -Wextra


.PHONY: clean
clean:
	rm -f vuln
