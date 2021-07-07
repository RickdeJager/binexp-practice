#include <unistd.h>

int main() {
    const char m[] = "Hello World :D\n";
    write(1, m, sizeof(m));
    return 0;
}

