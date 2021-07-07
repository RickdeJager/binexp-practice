
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {
    char newline[]="\n";
    for (int i = 0; i < argc; i++) {
        write(0, argv[i], strlen(argv[i]));
        write(0, newline, 1);
    }
}
