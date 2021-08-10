#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
void give_flag() {
    FILE *f = fopen("flag.txt", "r");
    if (f != NULL) {
        char c;
        while ((c = fgetc(f)) != EOF) {
            putchar(c);
        }
    }
    else {
        printf("Couldn't open flag file!\n");
    }
    fclose(f);
}

void vulnerable()
{
    char buf[8];
    gets(buf);
}

void main()
{
    setvbuf(stdin,NULL,_IONBF,0);
    setvbuf(stdout,NULL,_IONBF,0);
    printf("This is pwn_warmup, go\n");
    printf("&give_flag = %p\n", &give_flag);
    vulnerable();
}
