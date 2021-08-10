#include <stdio.h>
#include <string.h>
#define LISTSIZE 1337

int* generate() {
  static int list[LISTSIZE];
  int n_primes = 1;
  int i;
  int prime;

  list[0] = 2;

  for (i = 3; n_primes <= LISTSIZE; i += 2) {
    prime = 1;
    int j;
    for (j = 0; j < n_primes; j++) {
      if (i % list[j] == 0) {
        prime = 0;
      }
    }

    if (prime) {
      list[n_primes] = i;
      n_primes++;
    }
  }

  return list;
}

void rot(char* plain, int i) {
  const int len = strlen(plain);
  char temp;
  int j;

  for (j = 0; j < len; ++j) {
    temp = plain[j];
    if (temp != '_') {
      temp = (((temp - 97 + i) % 26) + 97);
    }
    plain[j] = temp;
  }
}

void shift(char* plain, int i) {
  const int len = strlen(plain);
  char copy[len];
  int j;

  strcpy(copy, plain);
  for (j = 0; j < len; j++) {
    plain[j] = copy[(j + i) % len];
  }
}

int main() {
  int* p;
  int i;
  char input[1000];

  p = generate();

  int correct = 0;
  while (correct == 0) {
    printf(
        "%s\n",
        "enter input with the form: flag_words_with_underscores_and_letters");
    scanf("%s", input);

    char output[strlen(input)];
    strcpy(output, input);

    for (i = 0; i < LISTSIZE; i++) {
      rot(output, p[i]);
      shift(output, p[i]);
    }

    if (strcmp(output,
               "azeupqd_ftq_cgqefuaz_omz_ymotuzqe_ftuzwu_bdabaeq_fa_o") == 0) {
      correct = 1;
    } else if (strcmp(output, "qe_mzp_xqffqderxms_iadpe_iuft_gzpqdeoad") == 0) {
      printf("%s\n", "very funny");
    } else {
      printf("%s\n", "incorrect");
    }
  }

  char correct_str[61];
  correct_str[0] = 'u';
  correct_str[1] = 'i';
  correct_str[2] = 'u';
  correct_str[3] = 'c';
  correct_str[4] = 't';
  correct_str[5] = 'f';
  correct_str[6] = '{';
  for (i = 0; i < 53; i++) {
    correct_str[i + 7] = input[i];
  }
  correct_str[60] = '}';
  printf("%s\n", correct_str);

  return 0;
}