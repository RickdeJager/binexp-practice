#include <stdlib.h>                                                                                 
#include <stdio.h>                                                                                  

int main(int argc, char** argv) { 
    char buf [1024];
  
    if (argc != 2) {
        puts("usage: ./echo-file [file_to_echo]");
        return 1;
    }

    FILE * fp = fopen(argv[1],"r");
    if (!fp) {
        puts("Failed to open file.");
        return 1;
    }

    while (fgets(buf, sizeof(buf), fp)) {
        printf("%s", buf);
    }
}
