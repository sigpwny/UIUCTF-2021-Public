If you read the patch or the description of the chal you see seccomp doesn't
NO_NEW_PRIVS anymore, which means you can make arbitrary syscalls in a more
privileged child process fail.

The exploit_me.c's code gives an obvious hint:

```C
if (!faccessat(AT_FDCWD, "/flag", R_OK, AT_EACCESS)) {
        fprintf(stderr, "You can't be root to execute this! ... or can you?\n");
        return 1;
}
```

It "checks" if it's root by checking if it can read `/flag`. We can just load
a seccomp filter to pretend it cannot, and we get a root shell.

The filter is simple enough to hand write cBPF assembly. The solution is in
`healthcheck/solution.c`.
