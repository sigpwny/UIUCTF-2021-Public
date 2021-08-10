from pwn import *
conn = remote('industrialization.chal.uiuc.tf',1337)
#conn = process('./challenge/server.py')
l_can = '<'
r_can = '>'

l_chg = '{'
r_chg = '}'

l_set = '('
r_set = ')'
idx = 0
print(conn.recvuntil('times!\n'))
while(True):
    line = conn.recvline()
    resp = line
    print(line)
    print(conn.recvuntil(b'> '))
    
    #i = 0
    sets = [b'(' + x.split(b')')[0] + b')' for x in line.split(b'(') if len(x) > 0]
   
    if sets[0] not in line:
        sets = sets[1:]
    #print(sets)
    for i in range(0,len(sets),2):
        #print(sets[i])
        #print(sets[i] in line)
        resp = resp.replace(sets[i],sets[i+1],1)
    

    changes = [b'{' + x.split(b'}')[0] + b'}' for x in line.split(b'{') if len(x) > 0]
    if changes[0] not in line:
        changes = changes[1:]
    for change in changes:
        fill = (b'A' * (len(change) - 2)) if change[1:-1] != (b'A' * (len(change) - 2)) else (b'B' * (len(change) - 2))
        changed = b'{' + fill + b'}'
        resp = resp.replace(change,changed,1)

    print(line)
    print(resp)
    print(idx)
    idx += 1
    if idx % 100 == 0:
        print(idx)
    '''
        print(sets,chngs,canaries,sep='\n')
        for c in line:
            #print("\'" + c + "\'")
            if c == l_chg:
                #print('change')
                content = line[i + 1:].split(r_chg)[0]
                #print("Content " + content)
                resp += b'{' + b'A' * len(content) + b'}'
                i += len(content) + 2
            elif c == l_can:
                #print('canary')
                content = line[i + 1:].split(r_can)[0]
                resp += b'<' + bytes(content.encode('utf-8')) + b'>'
                i += len(content) + 2
            elif c == l_set:
                print(f"'{line[i + 1]}'")
                content = line[i + 1:].split(r_set)[0]
            else:
                #print('filler')
                resp += bytes(c.encode('utf-8'))
                i += 1
    '''
    print(resp)
    conn.send(resp)
    #conn.interactive()
    servresp = conn.recvline()
    if b"Good" not in servresp:
        print(servresp)
        print(line)
        print(resp)
        conn.interactive()
        
    #conn.interactive()
   
        

        
