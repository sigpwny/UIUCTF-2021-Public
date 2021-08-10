// SPDX-License-Identifier: MIT
/*
 * Copyright 2021 Google LLC.
 */

#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/syscall.h>

int main(int argc, char *argv[])
{
	struct sock_filter insns[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_faccessat, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EACCES),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	unsigned short num_insns = sizeof(insns) / sizeof(insns[0]);

	printf("%hu\n", num_insns);
	for (unsigned short i = 0; i < num_insns; i++) {
		printf("%04hx %02hhx %02hhx %08x\n",
		       insns[i].code,
		       insns[i].jt,
		       insns[i].jf,
		       insns[i].k);
	}

	return 0;
}
