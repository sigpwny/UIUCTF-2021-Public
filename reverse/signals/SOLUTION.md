This program loads code to a writeable + executable memory region and forks before jumping to it. The loaded code decrypts itself by xor'ing with the corresponding input flag character. If the character is incorrect, then the code will "decrypt" to invalid instructions and therefore crash, prompting an incorrect flag by the parent process after receiving the signal from the child process. The code prints correct and exits if it is decrypted fully.

See the solver script written by Ravi in solver.py.
