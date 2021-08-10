#include <stdlib.h>
#include <stdio.h>

void main() {
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("Where to? ");
	long addr;
	scanf("%lu", &addr);
	((void(*)(void))addr)();
}
