The file provided is a ZScript as created by ZBrush.  A ZBrush installation is necessary to run the script, and will likely be needed for analysis.  A free 30-day trial is available for ZBrush so this is unlikely to be an issue.

It is necessary to discover the way ZSC files encode script content.  This can be done by creating sample ZScript TXT files, compiling them, and observing how the output ZSC file changes when the input changes.  For short ZScripts like this one, a procedure like the following suffices to recover the source text:

    def dx2(x, l):
        y = bytearray()
        while x:
            for i in range(126):
                if not x:
                    break
                l ^= x[0]
                x = x[1:]
                y.append(l)
            if x:
                l = y.pop() ^ x[0]
        return bytes(y)
    
    with open("FlagChecker.zsc", "rb") as f:
        data = f.read()
    
    data = data[0x9448:]
    length, = struct.unpack_from("<I", data, 12)
    data = data[4 * 6:][:length]

The source text discovered this way compares the flag character-by-character to hard-coded ASCII values.  These can be used to recover the flag like so:

    matches = re.findall(r"\[StrToAsc,flag,\d*]==(\d*)", decoded)
    flag = bytes(int(m) for m in matches)
    print(flag.decode())

It is likely that there are other ways to solve this challenge that do not directly involve understanding the file format -- for example, running ZBrush in a debugger and observing the process's memory may reveal the contents (I have not tried to see if this works or not).
