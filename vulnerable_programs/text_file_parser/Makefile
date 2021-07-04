CC ?= gcc

vuln: vuln.c
	${CC} -o vuln vuln.c -fno-stack-protector -no-pie -g -Wall -Wextra

.PHONY: clean
clean:
	rm -f vuln
