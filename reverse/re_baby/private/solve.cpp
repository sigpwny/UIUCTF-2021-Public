#include <string>
#include <vector>
#include <iostream>
using namespace std;

string rot(string source, int i) {
    string toReturn = "";
    for (int j = 0; j < source.size(); j++) {
        if (source[j] != '_') {
            toReturn += char(((((int) source[j]) - 97 + i) % 26) + 97);
        } else {
            toReturn += '_';
        }
    }
    return toReturn;
}

string shift(string source, int i) {
    string toReturn = source;
    int size = source.length();
    for (int j = 0; j < size; j++) {
        toReturn[j] = source[(j + i) % size];
    }
    return toReturn;
}

vector<int> generate(int max) {
    vector<int> list;
    list.push_back(2);
    int n = 3;
    while (list.size() < max) {
        bool add = true;
        for (int i = 0; i < list.size(); i++) {
            if (n % list[i] == 0) {
                add = false;
            }
        }

        if (add) {
            list.push_back(n);
        }

        n += 2;
    }

    return list;
}

int main() {


    // total number of times the input is rotated and shifted
    // = sum of the first 1337 primes
    long long int total = 0;
    vector<int> primes = generate(1337);
    for (int i = 0; i < primes.size(); i++) {
        total += primes[i];
    }

    cout << "total sum of primes: " << total << endl;


    string scrambled_flag = "azeupqd_ftq_cgqefuaz_omz_ymotuzqe_ftuzwu_bdabaeq_fa_o";

    // decrypt
    string unscrambled_flag = scrambled_flag;
    unscrambled_flag = shift(unscrambled_flag, unscrambled_flag.length() - total % unscrambled_flag.length());
    unscrambled_flag = rot(unscrambled_flag, 26 - (total % 26));
    cout << "unscrambled flag: " << unscrambled_flag << endl;


    // scrambled flag found in binary file for "very funny"
    scrambled_flag = "qe_mzp_xqffqderxms_iadpe_iuft_gzpqdeoad";

    // decrypt
    unscrambled_flag = scrambled_flag;
    unscrambled_flag = shift(unscrambled_flag, unscrambled_flag.length() - total % unscrambled_flag.length());
    unscrambled_flag = rot(unscrambled_flag, 26 - (total % 26));
    cout << "unscrambled flag: " << unscrambled_flag << endl;
    return 0;
}

// C CODE TO GENERATE THE SCRAMBLED STRINGS:
// char flag[] = "i_propose_to_consider_the_question_can_machines_think";
    
//     for (i = 0; i < LISTSIZE; i++) {
//         rot(flag, p[i]);
//         shift(flag, p[i]);
//     }
    
//     printf("%s\n", flag);

//     char funny[] = "flag_words_with_underscores_and_letters";
    
//     for (i = 0; i < LISTSIZE; i++) {
//         rot(funny, p[i]);
//         shift(funny, p[i]);
//     }
    
//     printf("%s\n", funny);