---
title: Introduction to Heap
date: '2025-06-03T10:00:00+05:30'
event: Blog Post
category: Concept
difficulty: Intermediate
author:
- VulnX
tags:
- pwn
- heap
- theory
description: '> This series is about the GNU allocatorhttps://www.gnu.org/software/libc/manual/2.34/html_node/TheGNUAllocator.html
  {: .promptinfo }  > Some informat...'
---
> This series is about the [GNU allocator](https://www.gnu.org/software/libc/manual/2.34/html_node/The-GNU-Allocator.html)
{: .prompt-info }

> Some information might be incorrect as I am creating these posts while learning myself
{: .prompt-warning }

## What is heap?

Heap
: Heap is a region of memory divided into chunks which are managed by the dynamic memory allocator.

- The GNU libc heap implementation uses the arena allocator for *fast memory allocation with minimal overhead*
- On the other hand FreeBSD & Linux kernel uses the [buddy allocator](https://en.wikipedia.org/wiki/Buddy_memory_allocation):
    1. SLOB ❌ ( removed from version 6.3, only used in IoT and other hardware constrained devices )
    2. SLAB ❌ ( deprecated )
    3. SLUB ✅ ( Unqueued slab allocator )
        - Why? For more flexible allocations (than the standard 4KiB page size), reduced fragmentation and to be more performant. Because all standard library implementations and other applications rely on the kernel. If the kernel is slow, nothing can be fast.

## Allocations

Allocations are typically of two types:

### Arena based allocations

- Works for small sized allocations
- Initially no heap segment exists in the process's virtual address space
- When you request memory from `malloc` the very first time, it creates the heap segment in the process's virtual address space by using the `brk` syscall. By default it allocates 0x21000 (33 pages of memory) for future allocations.

```c
#include <stdlib.h>

int main() {
	void *ptr = malloc(24);
}
```

```console
➜  heap gcc prog.c -g -o prog
➜  heap strace ./prog
execve("./prog", ["./prog"], 0x7ffce1c13b60 /* 74 vars */) = 0
...
brk(NULL)                               = 0x5609ea35a000
brk(0x5609ea37b000)                     = 0x5609ea37b000
exit_group(0)                           = ?
+++ exited with 0 +++
```

memory map (before malloc):
```
             Start                End Perm     Size Offset File
    0x555555554000     0x555555555000 r--p     1000      0 prog
    0x555555555000     0x555555556000 r-xp     1000   1000 prog
    0x555555556000     0x555555557000 r--p     1000   2000 prog
    0x555555557000     0x555555558000 r--p     1000   2000 prog
    0x555555558000     0x555555559000 rw-p     1000   3000 prog
...
```

memory map (after malloc):
```
             Start                End Perm     Size Offset File
    0x555555554000     0x555555555000 r--p     1000      0 prog
    0x555555555000     0x555555556000 r-xp     1000   1000 prog
    0x555555556000     0x555555557000 r--p     1000   2000 prog
    0x555555557000     0x555555558000 r--p     1000   2000 prog
    0x555555558000     0x555555559000 rw-p     1000   3000 prog
    0x555555559000     0x55555557a000 rw-p    21000      0 [heap]
...
```

- this 0x21000 bytes contiguous region of memory from which chunks are taken (to be given to user via `malloc`) and returned (from the user via `free`) is known as an "arena".

### Memory mapped allocations

- Works for large size allocations ( > 128 KiB )
- Since these allocations are much larger than the arena itself so it doesn't make sense to extent its boundary again via `brk` for every large allocation. Instead, these requests can be served via directly `mmap`-ing them
- Downside: Involves syscall for every large request and is thus slower
- Advantage: Since the memory comes directly from the kernel, it is already NULL-ed out, so no previous state management or cleaning overhead. Also this provides 0 external fragmentation since the mapping is created directly for the chunk and `free`-ing it means genuinely deallocating the memory back to the OS. This avoids the freed chunks from being "locked" between two (a case observable in arena based allocations)

> The 128 KiB size for large allocations is not fixed. It can be changed manually via [mallopt()](https://man7.org/linux/man-pages/man3/mallopt.3.html)
{: .prompt-tip }

```c
#include <stdlib.h>
#include <stdio.h>

int main() {
	size_t small = 24;
	size_t large = 200 * 1024;
	void *p1 = malloc(small); // allocated from the arena
	void *p2 = malloc(large); // allocated directly via mmap
	printf("p1 = %p | p2 = %p\n", p1, p2);
	asm("int3");
}
```

```
➜  heap strace ./prog
execve("./prog", ["./prog"], 0x7ffda8a7ceb0 /* 74 vars */) = 0
...
mmap(NULL, 208896, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7ffff7d6e000
```

```
p1 = 0x5555555592a0 | p2 = 0x7ffff7d6e010
             Start                End Perm     Size Offset File (set vmmap_prefer_relpaths on)
    0x555555554000     0x555555555000 r--p     1000      0 prog
    0x555555555000     0x555555556000 r-xp     1000   1000 prog
    0x555555556000     0x555555557000 r--p     1000   2000 prog
    0x555555557000     0x555555558000 r--p     1000   2000 prog
    0x555555558000     0x555555559000 rw-p     1000   3000 prog
    0x555555559000     0x55555557a000 rw-p    21000      0 [heap]
    0x7ffff7d6e000     0x7ffff7da4000 rw-p    36000      0 [anon_7ffff7d6e]
...
```
