#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// uiuctf{y0u_f0unD_t43_fl4g_w0w_gud_j0b}

int main(int argc, char *argv[]) {
    unsigned char buffer[40];
    printf("Enter the flag:\n");
    fgets(buffer,40,stdin);

    int i;
    for (i = 0; i < 39; i++) {
        buffer[i] = (((buffer[i] + 59) ^ 0xF78063EF)) ^ 0x9F14CFD7;
     }
    buffer[i] = 0;

    for (i = 0; i < 39; i++) {
        buffer[i] = (((buffer[i] + 18) ^ 0xB168C552)) ^ 0x5E3307AF;
    }
    buffer[i] = 0;

    for (i = 0; i < 39; i++) {
        buffer[i] = (((buffer[i] + 4) ^ 0x5258EFD1)) ^ 0x25DB9B81;
    }
    buffer[i] = 0;

    for (i = 0; i < 39; i++) {
        buffer[i] = (((buffer[i] + 19) ^ 0xE856BBFB)) ^ 0x97DEA993;
    }
    buffer[i] = 0;

    for (i = 0; i < 39; i++) {
        buffer[i] = (((buffer[i] + 12) ^ 0x54FC78E8)) ^ 0x9DF87491;
    }
    buffer[i] = 0;

    for (i = 0; i < 39; i++) {
        buffer[i] = (((buffer[i] + 12123324) ^ 0x5D1F4C6)) ^ 0xC7340566;
    }
    buffer[i] = 0;

    for (i = 0; i < 39; i++) {
        buffer[i] = (((buffer[i] + 893249034) ^ 0xE411081C)) ^ 0x5258EFD1;
    }
    buffer[i] = 0;

    for (i = 0; i < 39; i++) {
        buffer[i] = (((buffer[i] + 2039224) ^ 0x7D335ACB)) ^ 0x9DF87491;
    }
    buffer[i] = 0;

    for (i = 0; i < 39; i++) {
        buffer[i] = (((buffer[i] + 504843) ^ 0x2012CCDB)) ^ 0xC7340566;
    }
    buffer[i] = 0;

    for (i = 0; i < 39; i++) {
        buffer[i] = (((buffer[i] + 3204321) ^ 0xCD5950F1)) ^ 0xE411081C;
    }
    buffer[i] = 0;

    for (i = 0; i < 39; i++) {
        buffer[i] = (((buffer[i] + 234309) ^ 0x72753AEA)) ^ 0xD03DF7C8;
    }
    buffer[i] = 0;

    for (i = 0; i < 39; i++) {
        buffer[i] = (((buffer[i] + 8954302) ^ 0x54FC78E8)) ^ 0xC8788683;
    }
    buffer[i] = 0;

    for (i = 0; i < 39; i++) {
        buffer[i] = (((buffer[i] + 2344154) ^ 0x54AC79E8)) ^ 0xC8799683;
    }
    buffer[i] = 0;

    for (i = 0; i < 39; i++) {
        buffer[i] = (((buffer[i] + 9021302) ^ 0x45FC7779)) ^ 0xD8766683;
    }
    buffer[i] = 0;

    for (i = 0; i < 39; i++) {
        buffer[i] = (((buffer[i] + 4930582) ^ 0x542278E8)) ^ 0x22788683;
    }
    buffer[i] = 0;

    for (i = 0; i < 39; i++) {
        buffer[i] = (((buffer[i] + 3452341) ^ 0x12FC78E8)) ^ 0xC8712683;
    }
    buffer[i] = 0;

    for (i = 0; i < 39; i++) {
        buffer[i] = (((buffer[i] + 9034125) ^ 0x16FC7817)) ^ 0xC8168173;
    }
    buffer[i] = 0;

    for (i = 0; i < 39; i++) {
        buffer[i] = (((buffer[i] + 85435402) ^ 0x33FC34E8)) ^ 0xC8338343;
    }
    buffer[i] = 0;

    for (i = 0; i < 39; i++) {
        buffer[i] = (((buffer[i] + 1395043) ^ 0x54987898)) ^ 0xC9889683;
    }
    buffer[i] = 0;

    for (i = 0; i < 39; i++) {
        buffer[i] = (((buffer[i] + 349141) ^ 0x23FC7873)) ^ 0xC8732383;
    }
    buffer[i] = 0;

    for (i = 0; i < 39; i++) {
        buffer[i] = (((buffer[i] + 2343285) ^ 0x54FC78E8)) ^ 0xC8788683;
    }
    buffer[i] = 0;
    
    int array4[40] = {77, 185, 77, 11, 212, 102, 227, 41, 184, 77, 223, 102, 184, 77, 14, 196, 223, 212, 20, 59, 223, 102, 44, 20, 71, 223, 183, 184, 183, 223, 71, 77, 164, 223, 50, 184, 234, 245, 146};

    for (i = 0; i < 39; i++) {
        if (buffer[i] != array4[i]) {
            printf("WRONG!");
            return 0;
        }
    }

    printf("GOOD JOB!");

    return 0;
}