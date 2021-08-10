#include <dos.h>
#include <mem.h>
#include <process.h>
#include <stdio.h>
#include <string.h>

/*
All you have to do is enter "HOT" to get the flag. 
This binary is not meant to be reversed since it is 
part of a forensics challenge. However, some obfuscation 
was done to prevent hex editors from picking it up 
and force people to actually run MS-DOS :)

Compile with Turbo C v2.01 on MS-DOS:
https://web.archive.org/web/20060516050946/http://community.borland.com/article/0,1410,20841,00.html

- WhiteHoodHacker
*/

void main() {
  /* "ut3", check string used to determine if input is correct by solving three characters of the flag */
  char chk[] = "\x75\x74\x33";
  /* Flag XOR'd by "TOH" */
  char enc[] = "\x21\x26\x3d\x37\x3b\x2e\x2f\x1d\x7b\x27\x1b\x78\x26\x2a\x17\x32\x7f\x1a\x0b\x02\x78\x26\x2a\x35";
  char key[3];
  char out[22];
  int i;

  clrscr();
  printf("SUPER\n\n> ");

  while (1) {
    char finishIt[5];
    scanf("%4s", finishIt);
    fflush(stdin);

    /* Last character of 4 byte string is a null terminator, meaning the entered string is 3 bytes or less */
    if (finishIt[3] == 0) {
      /* Reverse "HOT" to "TOH" for the key (since I kinda XOR by HOT already in the original forensics challenge) */
      key[0] = finishIt[2];
      key[1] = finishIt[1];
      key[2] = finishIt[0];

      /* checks if input decodes the flag correctly */
      if (chk[0] == (enc[0] ^ key[0]) && chk[1] == (enc[4] ^ key[1]) && chk[2] == (enc[8] ^ key[2])) {
	      for (i=0; i<strlen(enc); i++) {
	        char tmp = enc[i] ^ key[i%3];
	        out[i] = tmp;
	      }
	      out[i] = '\0';
	      puts(out);
	      exit(0);
      }
      else {
	      printf("FINISH IT.\n\n> ");
      }
    }
    else {
      printf("FINISH IT.\n\n> ");
    }
  }
}