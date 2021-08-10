#include <stdio.h>
#include <math.h>
#include "factors.c"

// gcc main.c -o challenge -lm

int main() {

    int inputs[5] = {-1, -1, -1, -1, -1};
    int outputs[5] = {-1, -1, -1, -1, -1};

    // 19753
    int count = 0;
    while (1) {
        if (count == 5) {
            for (int i = 4; i >= 0; i--) {
                int modder = (i + 1) * 19753;
                if (inputs[i] % modder != 0) {
                    return 0;
                }
            }
            printf("Congratulations, you found the secret inputs!\n");
            return 0; 
        }

        int n = 0;
        printf("Enter a number smaller than 100000: ");
        int result = scanf("%d", &n);

        if (result != 1) {
            printf("Bad input\n");
            return 0;
        }

        if (n > 1000000 || n < 0) {
            printf("Bad inputs\n");
            return 0;
        }

        inputs[count] = n;
        printf("Max prime factor: %d\n", getMaxPrimeFactor(n));
        outputs[count] = getMaxPrimeFactor(n);
        count++;
    }
    return 0;
}