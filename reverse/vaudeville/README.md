This challenge implements a challenge/reponse protocol that selects a random challenge, XOR shifts it 140 times, and compares it to the response from the user, which is XOR shifted 7 times. If the values match, it prints the contents of flag.txt to stdout.

The goal of this challenge was to be impossible for symbolic excutors to solve (due to weird syscall usage), tedious from looking at the disassembly, but relatively easy from running `strace` and staring at the traces for a while. To do that, it implements the XOR shifter by writing each bit into a file and using `lseek` to do the shifting, and then forking and writing two buffers of "random" text into a pipe and taking the length of the output string to do the XOR'ing. 

If I'm not around and people are asking for hints, "have you tried strace" is probably appropriate.
