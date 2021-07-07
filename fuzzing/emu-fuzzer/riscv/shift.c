// Takes your input from argv1, converts it to a decimal int, then shifts it and returns
// the result as exit code.

#include <unistd.h>
#include <stdlib.h>

int main(int argc, char**argv) {
    if (argc > 1) {
        long int inp = strtol(argv[1], NULL, 10);
        return inp << 1;
    }
    const char m[] = "Provide an argument please.\n";
    write(1, m, sizeof(m));
    return 0;
}
