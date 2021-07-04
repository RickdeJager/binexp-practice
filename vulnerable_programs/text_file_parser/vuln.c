/*
 * This is a simple program I wrote to test my fuzzer. It takes a custom file format and parses
 * it (badly). Beyond just getting crashes, I also want to make sure it's exploitable with ROP,
 * so the logic has been split over a bunch of unnecessary functions to get some more gadgets.
 *                                                                                                  
 * File format:                                                                                     
 *                                                                                                  
 * [$num_lines]                                                                                     
 * [$line_length $line_contents]                                                                    
 *                                                                                                  
 */                                                                                                 
                                                                                                    
#include <stdlib.h>                                                                                 
#include <stdio.h>                                                                                  
                                                                                                    
#define MAX_LINE_LEN 50                                                                             
                                                                                                    
void print_usage() {                                                                                
        puts("Usage: ./vuln [vulnfile.vf]");                                                        
        return;                                                                                     
}                                                                                                   
                                                                                                    
int get_num_lines(FILE * fp, int * num_lines) {                                                     
    int err = fscanf(fp, "%d", num_lines);                                                          
                                                                                                    
    if (err == 0) {                                                                                 
        puts("Failed to parse header");                                                             
        return 1;                                                                                   
    }                                                                                               
    return 0;                                                                                       
}
                                                                                                    
int get_line_length(FILE * fp) {                                                                    
    int num_lines;                                                                                  
    int err = fscanf(fp, "%d ", &num_lines);                                                        
                                                                                                    
    if (err == 0) {                                                                                 
        puts("Failed to line length");                                                              
        return -1;                                                                                  
    }                                                                                               
    return num_lines;                                                                               
}                                                                                                   

int get_command(char * buf, char * command) {
    FILE * cmd = popen(command, "r");
    if (cmd) {
        if (fgets(buf, MAX_LINE_LEN, cmd))
            return 1;
    }
    return 0;
}
                                                                                                    
int main(int argc, char** argv) { 
    char buf [MAX_LINE_LEN];
  
    if (argc != 2) {
        print_usage();
        return -1;
    }

    FILE * fp = fopen(argv[1],"r");
    if (!fp) {
        puts("Failed to open file.");
        return 1;
    }
    int num_lines = 0;
    int err = get_num_lines(fp, &num_lines);
    if (err) {
        return -1;
    }

    // Yes, I realise how cheesy this is.
    printf("Starting parser at: ");
    if (get_command(buf, "date"))
        puts(buf);

    printf("File contains %d lines.\n",num_lines);
    for (int i = 0; i < num_lines; i++) {
        int line_length = get_line_length(fp);
        if (line_length < 0) {
            puts("Failed to parse line length");
            return 1;
        }

        int bytes_read = fread(buf, 1, line_length, fp);

        buf[bytes_read] = '\0';
        printf("Line %d: %s\n",i, buf);
    }
    return 0;
}
