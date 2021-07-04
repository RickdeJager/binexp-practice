#include <unistd.h>

int main() {
    const char m[] = "Hello World :D\n";
    write(0, m, sizeof(m));
    return 0;
}

