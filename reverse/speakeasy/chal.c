#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include <winnt.h>
#include <WinCon.h>
#include <synchapi.h>

// Flag: uiuctf{D0nt_b3_@_W3T_bl4nK3t_6n7a}
/* Correct Final State
3D 44 71 89 D5 C1 36 A6
83 83 DF C6 96 A9 20 57
74 E4 DE B4 D7 A6 46 33
42 8A DB 76 1E 0B AE FA
76 69
*/
// Function names starting with "e_" are vmprotected

#define FLAG_LEN 34

#define RESET_TEXT      "\x1b[0m"
#define BOLD_TEXT       "\x1b[1m"
#define NON_BOLD_TEXT   "\x1b[22m"
#define RED_TEXT        "\x1b[31m"
#define GREEN_TEXT      "\x1b[32m"
#define YELLOW_TEXT     "\x1b[33m"
#define WHITE_TEXT      "\x1b[37m"

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

// Make real iv hard to pick out in data section
// None of these will show any references anyways
const uint8_t fake_iv_1[] =   { 0x3a, 0x04, 0x28, 0xa1, 0x7e, 0xfe, 0xe3, 0x0c, 
                                0x92, 0xff, 0xbb, 0xf4, 0xc1, 0xb5, 0xec, 0x49,
                                0x78, 0xa4, 0x3d, 0xe0, 0x4e, 0xd8, 0xcc, 0x01, 
                                0x90, 0x3b, 0xf2, 0xd4, 0x16, 0x92, 0x6b, 0x6b, 
                                0xdb, 0x34 };
const uint8_t fake_iv_2[] =   { 0x21, 0x7c, 0x44, 0x3e, 0xe8, 0x92, 0x4c, 0x68, 
                                0x79, 0xb6, 0x87, 0x52, 0xd8, 0x84, 0x12, 0x06, 
                                0xc5, 0xe9, 0xf8, 0xec, 0x82, 0x44, 0x78, 0x04, 
                                0x9f, 0x1c, 0x3f, 0x55, 0xfc, 0x00, 0x55, 0x31, 
                                0x45, 0x5b };
const uint8_t fake_iv_3[] =   { 0xb3, 0xc4, 0xde, 0x4b, 0x65, 0xc4, 0xae, 0x12, 
                                0x72, 0x9d, 0x59, 0xfa, 0x33, 0x46, 0xc7, 0x16, 
                                0x32, 0xe2, 0x53, 0x80, 0x4e, 0x24, 0x5a, 0x12, 
                                0x3c, 0x6a, 0xa9, 0x89, 0x21, 0xfa, 0xba, 0xa3, 
                                0x9a, 0x8d };
const uint8_t iv[] =          { 0x45, 0x33, 0x75, 0xa7, 0xa2, 0xd9, 0x64, 0xe5, 
                                0xe2, 0xc6, 0x88, 0xf9, 0xd2, 0xfa, 0x0f, 0x15,
                                0x7c, 0xba, 0xd0, 0xc4, 0xf4, 0xb4, 0x2d, 0x42, 
                                0x79, 0xf5, 0xfb, 0x03, 0x56, 0x54, 0xc0, 0xc8, 
                                0x0f, 0x04 };
const uint8_t fake_iv_4[] =   { 0xa5, 0xc7, 0xd4, 0x7e, 0x45, 0xa5, 0xfd, 0xfa, 
                                0x26, 0x5c, 0x2b, 0x15, 0x0b, 0xee, 0x93, 0xe3, 
                                0x04, 0x7e, 0xa5, 0x3f, 0xa1, 0xb7, 0x9b, 0x0d, 
                                0x71, 0xcf, 0x71, 0x24, 0x7b, 0x7a, 0x5d, 0x80, 
                                0x9e, 0x57 };
const uint8_t iv_2[] =        { 0x1b, 0x3d, 0xe2, 0x9b, 0x07, 0xfd, 0x52, 0x0f, 
                                0xa3, 0x57, 0x46, 0xc1, 0x4c, 0xc1, 0xe0, 0x05, 
                                0xaf, 0x12, 0x7a, 0x48, 0xf8, 0xe0, 0x0e, 0x8b, 
                                0xaa, 0x68, 0x27, 0x03, 0x2f, 0xd2, 0x01, 0x0b, 
                                0x30, 0x21  };
const uint8_t fake_iv_6[] =   { 0x27, 0xdc, 0xe1, 0x94, 0xd2, 0x8d, 0x20, 0x98, 
                                0xe4, 0x83, 0xd0, 0x61, 0x42, 0xf2, 0x0a, 0xd7, 
                                0xce, 0xcd, 0x8e, 0x21, 0xff, 0xf4, 0x52, 0x12, 
                                0x26, 0x93, 0xbd, 0x4f, 0x4d, 0x57, 0x8e, 0x81, 
                                0x99, 0xd6 };
const uint8_t fake_iv_7[] =   { 0x07, 0x66, 0x3b, 0x41, 0x12, 0xce, 0x5e, 0x45, 
                                0x7f, 0x8e, 0x11, 0x40, 0x4d, 0x5a, 0x1c, 0x5c, 
                                0x4d, 0x99, 0x57, 0x00, 0xdd, 0xb7, 0xf1, 0xc7, 
                                0xdf, 0x49, 0x72, 0xd1, 0x45, 0x24, 0x4c, 0x3d, 
                                0x3c, 0x19 };
const uint8_t fake_iv_8[] =   { 0x77, 0x5b, 0x7b, 0xb9, 0x0f, 0xa8, 0xb5, 0xf1, 
                                0x9b, 0x94, 0xaf, 0xb4, 0x3b, 0x01, 0xf4, 0xe9, 
                                0x0e, 0xf3, 0x69, 0x3f, 0xe4, 0x5a, 0xed, 0x8c, 
                                0x2c, 0x50, 0x5f, 0x31, 0x50, 0x26, 0x14, 0x03, 
                                0xfb, 0xc0 };

// Couple of fake funcs to make vtil output a bit more complex
void e_fake_func_1() {
    uint64_t sum = 0x1337;
    for (size_t i = 0; i < sizeof(fake_iv_2); i++) {
        sum += fake_iv_2[i];
    }
}
void e_fake_func_2() {
    uint8_t num = fake_iv_7[3] ^ fake_iv_7[0];
}
void e_fake_func_3() {
    uint64_t big_num = *(uint64_t*)fake_iv_1;
    big_num *= *(uint64_t*)fake_iv_3;
    big_num *= *(uint64_t*)fake_iv_8;
}

/*void hexdump(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}*/

void print(char* text) {
    for (int i = 0; i < strlen(text); i++) {
        putchar(text[i]);
        fflush(stdout);
        Sleep(40);
    }
    Sleep(200);
}

// ;)
size_t e_easter_egg() {
    // https://twitter.com/gf_256/status/1207199642737369088
    char buf[54];
    buf[0] = 'h';
    buf[1] = 't';
    buf[2] = 't';
    buf[3] = 'p';
    buf[4] = 's';
    buf[5] = ':';
    buf[6] = '/';
    buf[7] = '/';
    buf[8] = 't';
    buf[9] = 'w';
    buf[10] = 'i';
    buf[11] = 't';
    buf[12] = 't';
    buf[13] = 'e';
    buf[14] = 'r';
    buf[15] = '.';
    buf[16] = 'c';
    buf[17] = 'o';
    buf[18] = 'm';
    buf[19] = '/';
    buf[20] = 'g';
    buf[21] = 'f';
    buf[22] = '_';
    buf[23] = '2';
    buf[24] = '5';
    buf[25] = '6';
    buf[26] = '/';
    buf[27] = 's';
    buf[28] = 't';
    buf[29] = 'a';
    buf[30] = 't';
    buf[31] = 'u';
    buf[32] = 's';
    buf[33] = '/';
    buf[34] = '1';
    buf[35] = '2';
    buf[36] = '0';
    buf[37] = '7';
    buf[38] = '1';
    buf[39] = '9';
    buf[40] = '9';
    buf[41] = '6';
    buf[42] = '4';
    buf[43] = '2';
    buf[44] = '7';
    buf[45] = '3';
    buf[46] = '7';
    buf[47] = '3';
    buf[48] = '6';
    buf[49] = '9';
    buf[50] = '0';
    buf[51] = '8';
    buf[52] = '8';
    buf[53] = '\0';
    return strlen(buf);
}

uint8_t e_init_state(uint8_t i, uint8_t flag_char) {
    return flag_char ^ iv[i];
}

uint8_t e_update_state(uint8_t i, uint8_t state_char) {
    return state_char ^ (iv_2[i] >> 1);
}

void e_hidden_function(uint64_t useless, uint8_t* state) {
    uint8_t* correct_state = (uint8_t*)&__ImageBase.e_res2[19];
    print("\n");
    if (!memcmp(state, correct_state, FLAG_LEN)) {
        printf(GREEN_TEXT);
        print("Welcome!\n");
        print("Have a good time and don't go half-seas over\n");
    }
    else {
        printf(RED_TEXT);
        print("Go chase yourself, bull!\n");
        print("Come back with a warrant\n");
        e_fake_func_2();
    }
}

void e_call_hidden_function(uint8_t* state) {
    uint64_t func_address = *(uint64_t*)&__ImageBase.e_res[0];
    func_address += (uint64_t)&__ImageBase;
    
    // Extra (useless) arg added to make arguments more clear in VTIL
    ((void (*)(uint64_t, uint8_t*))func_address)(0, state);
    e_fake_func_3();
}

void check_flag(char* flag) {
    uint8_t state[40];

    for (uint8_t i = 0; i < sizeof(state); i++) {
       state[i] = e_init_state(i, flag[i]);
    }

    for (uint8_t i = 0; i < strlen(flag); i++) {
        state[i] = e_update_state(i, state[i]);
    }

    // Print final state for changing flag
    // hexdump(state, sizeof(state));
    e_call_hidden_function(state);
}

int main(int argc, char** argv) {
    e_easter_egg();
    
    printf(BOLD_TEXT);
    print("The year is 1923.\n");
    print("You recently moved to Chicago and your friend told you about the local speakeasy.\n");
    print("Great! But, this friend left out one key detail");
    print(".");
    print(".");
    print(".\n");
    print("The password to get in!\n\n");

    printf(NON_BOLD_TEXT);
    printf(YELLOW_TEXT);
    print("Good evening. Welcome to the juice joint.\n");
    print("My apologies, but I can't let you in without the password.\n");
    print("I know you want to get zozzled just like everyone else, but I can't just let you walk in here.\n\n");

    printf(BOLD_TEXT);
    printf(WHITE_TEXT);
    print("You fumble your words and muster out");
    print(".");
    print(".");
    print(".\n");
    printf(RESET_TEXT);

    char flag[100];  
    gets(flag);
    check_flag(flag);

    e_fake_func_1();

    printf(RESET_TEXT);
    return 0;
}