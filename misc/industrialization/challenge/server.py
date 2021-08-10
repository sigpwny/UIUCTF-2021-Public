#!/usr/bin/env python3
import string
import random
import sys

# Put your imports at the top
def print_flag():
  f = open('flag.txt', 'rb')
  ret = f.read()
  f.close()
  sys.stdout.buffer.write(ret)

ignore_list = [0x28,0x29,0x7B,0x7D,0x3C,0x3E]
noise_vals = [bytes([b]) for b in [x for x in bytes(list(range(33,127))) if x not in ignore_list]]
l_can = b'<'
r_can = b'>'

l_chg = b'{'
r_chg = b'}'

l_set = b'('
r_set = b')'

def gen_filler(n,l=0):
    ret = b''
    for i in range(random.randrange(l,n)):
        ret += random.choice(noise_vals)
    return ret

# TODO Change this to allow for arbitrary sizes
def make_buf():
    c_left = 10
    buf = b''
    pos = 0
    rs_queue = []
    checks = []
    while c_left > 0:
        action = random.randint(0,3)
        if action == 0: #Canary
            #sys.stdout.buffer.write(f"Canary {pos}")
            check = {'type':'can','pos':pos + 1,'val':gen_filler(8,l=2)}
            buf += l_can + check['val'] + r_can
            pos += len(check['val']) + 2
            checks.append(check)
        elif action == 1: #Change
            #sys.stdout.buffer.write(f'Change {pos}')
            check = {'type':'chg','pos':pos + 1,'val':gen_filler(8,l=2)}
            buf += l_chg + check['val'] + r_chg
            pos += len(check['val']) + 2
            checks.append(check)
        elif action == 2: #Set A to B
            if len(rs_queue) > 0:
                #sys.stdout.buffer.write(f'Set Src {pos}')
                check = rs_queue[0]
                rs_queue.pop()
                check['src'] = pos + 1
                fill = gen_filler(len(check['val']) + 1,l=len(check['val']))
                check['val'] = fill
                buf += l_set + fill + r_set
                pos += len(check['val']) + 2
                checks.append(check)
            else:
                #sys.stdout.buffer.write(f'Set Dst {pos}')
                check = {'type':'set','dest': pos + 1, 'src': None, 'val':gen_filler(8,l=2)}
                buf += l_set + check['val'] + r_set
                pos += len(check['val']) + 2
                rs_queue.append(check)
        else: #Filler
            #sys.stdout.buffer.write(f'Filler {pos}')
            fill = gen_filler(32,l=2)
            buf += fill
            pos += len(fill)
        c_left -= 1

    while len(rs_queue) > 0:
        #sys.stdout.buffer.write(f'Set Src {pos}')
        check = rs_queue[0]
        rs_queue.pop()
        #sys.stdout.buffer.write(rs_queue)
        check['src'] = pos + 1
        fill = gen_filler(len(check['val']) + 1,l=len(check['val']))
        check['val'] = fill
        buf += l_set + fill + r_set
        pos += len(check['val']) + 2
    

    return buf,checks

def print_buffer(b):
    for i in range(len(b)):
      if i % 16 == 0:
        sys.stdout.buffer.write("\n" + hex(i)[2:].zfill(8) + ': ',end='')
        sys.stdout.buffer.write(hex(b[i])[2:].zfill(2),end='')
      elif i % 2 == 0:
        sys.stdout.buffer.write(' ',end='')
        sys.stdout.buffer.write(hex(b[i])[2:].zfill(2),end='')
      else:
        sys.stdout.buffer.write(hex(b[i])[2:].zfill(2),end='')

    if (len(b) % 16 != 0):
      for i in range(len(b), len(b) + (16 - len(b) % 16)):
        if i % 2 == 0:
          sys.stdout.buffer.write(' 00',end='')
        else:
          sys.stdout.buffer.write('00',end='')
    sys.stdout.buffer.write('')

def print_bytes(b):
    sys.stdout.buffer.write(b)
    sys.stdout.buffer.flush()

def check_solution(buf,checks,resp):

    for check in checks:
        if check['type'] == 'chg' and resp[check['pos']:check['pos']+len(check['val'])] == check['val']:
            sys.stdout.buffer.write(b"Failed! Actual:"+resp[check['pos']:check['pos']+len(check['val'])]+ b"Current:"+check['val'])
            return False
        if check['type'] == 'can' and resp[check['pos']:check['pos']+len(check['val'])] != check['val']:
            sys.stdout.buffer.write(b"Failed! Actual:"+resp[check['pos']:check['pos']+len(check['val'])]+b"Correct:"+check['val'])
            return False
        if check['type'] == 'set' and resp[check['dest']:check['dest']+len(check['val'])] != check['val']:
            sys.stdout.buffer.write(b"Failed! Actual:"+resp[check['dest']:check['dest']+len(check['val'])]+b"Correct:"+check['val'])
            return False
    return True

def gen_challenge(viewmode):
    buf,checks = make_buf()
    if viewmode == 'hexdump':
        print_buffer(buf)
    elif viewmode == 'bytes':
        print_bytes(buf)
    sys.stdout.buffer.write(b'\nInput > ')
    sys.stdout.buffer.flush()
    resp = input()
    if type(resp) == str:
        resp = resp.encode()
    return check_solution(buf,checks,resp)
      
def main():
    sys.stdout.buffer.write(b'Welcome to the bufactory, where we make and fix buffers!\nWe havent exactly figured out what the rules are, but here are some right and wrong examples.\n')
    sys.stdout.buffer.write(b'GOOD - "{Cheeseburger}<Pizza>(Fries)(Sodas)" -> "{Cheeeeboogor}<Pizza>(Sodas)(Stuff)"\n')
    sys.stdout.buffer.write(b'BAD  - "{Cheeseburger}<Pizza>(Fries)(Sodas)" -> "{Cheeseburger}<Peeza>(Tacos)(Stuff)"\n')
    sys.stdout.buffer.write(b'GOOD - "{AAAA}FILLER(BBBB)FILLER{CCCC}FILLER<DDDD>FILLER(EEEE)FILLER" -> "{BBBB}FILLER(EEEE)FILLER{DDDD}FILLER<DDDD>FILLER(GGGG)FILLER"\n')
    sys.stdout.buffer.write(b'BAD  - "{AAAA}FILLER(BBBB)FILLER{CCCC}FILLER<DDDD>FILLER(EEEE)FILLER" -> "{AAAA}FILLER(DDDD)FILLER{CCCC}FILLER<EEEE>FILLER(FFFF)FILLER"\n')
    sys.stdout.buffer.write(b"Ok now you try a few times!\n")
    sys.stdout.buffer.flush()
    num = 100
    for i in range(num):
        if gen_challenge('bytes') == True:
            if i < num - 1:
                sys.stdout.buffer.write(b"Good Job keep going\n")
                sys.stdout.buffer.flush()
            else:
                with open("flag.txt", "rb") as flag_file:
                    sys.stdout.buffer.write(flag_file.read()+b"\n")
                    sys.stdout.buffer.flush()
        else:
            sys.stdout.buffer.write("Exiting...\n")
            sys.stdout.buffer.flush()
            exit()

if __name__ == "__main__":
    main()
