# Written by Ravi

# Run gdb signals, then source solver.py

import gdb
FIRST_CHUNK = 0x555555558020
FLAG = 'uiuctf{'
def solve_chunk():
    global FLAG
    byte_val = 0x48

    while byte_val == 0x48:
        gdb.execute('b *($pc + 0x1b)')
        gdb.execute('c')
        gdb.execute('si')
        byte_read = gdb.execute('x/1c $pc', to_string=True).split(":")[1].strip().split("'")[0]

        # byte_val = int(byte_read, 16) # for peda
        byte_val = int(byte_read) # for vanilla gdb

        if (byte_val == 0x48):
            print("Found solved chunk!")
            continue
        else:
            new_chr = chr(byte_val ^ 0x48)
            FLAG += new_chr
            print("Current guess: " + FLAG)

            if (new_chr == '}'):
                print("Done!")
                exit(0)

            break

def main():
    while True:
        gdb.execute('set follow-fork-mode child')
        gdb.execute('set pagination off')
        gdb.execute('file signals')
        gdb.execute(f'b *{FIRST_CHUNK}')
        gdb.execute(f'run {FLAG}')
        solve_chunk()

if __name__ == "__main__":
    main()
