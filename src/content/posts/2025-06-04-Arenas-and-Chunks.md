---
title: Arenas and Chunks
date: '2025-06-04T10:00:00+05:30'
event: Blog Post
category: Concept
difficulty: Intermediate
author:
- VulnX
tags:
- pwn
- heap
- theory
description: 'Arena : An arena is a memory management structure in glibc''s malloc
  implementation that manages a contiguous region of memory from the heap. It organi...'
---
Arena
: An arena is a memory management structure in `glibc`'s `malloc` implementation that manages a contiguous region of memory from the heap. It organizes memory into chunks, provides synchronization for thread-safe access, and allows multiple threads to allocate memory concurrently without excessive contention.

Chunks
: A chunk is a block of memory within an arena, allocated from the contiguous region managed by the arena. Each chunk has metadata that tracks its size and allocation status, allowing it to be allocated or freed as needed.

# Arena

- A single-threaded program typically has only one arena, known as the main arena. This is where your usual `malloc` allocations come from.
- But a multithreaded process may have more than one arena to allow the thread to manage memory more efficiently without relying on `mutex` for thread synchronization.
- So every thread has a dedicated arena? **NO**, as this would lead to severe resource depletion. In fact, the maximum number of arenas a process can have at a single point is capped at $8 \times \text{number of CPU cores}$.
- If a new thread is created and no separate arena can be created for it, then it finds an already *available* arena (that which does not currently hold the `mutex` lock) and attaches itself to it.
- The address of the arena, number of attached threads and other chunks/bins information is tracked by `GLIBC` with the help of the [`malloc_state` struct](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L1830) as a global variable.

# Chunks

- In `GLIBC`'s memory allocation system, a chunk is the basic unit of memory management used internally by malloc, free, and related functions.
- When memory is requested, malloc carves out a chunk from an arena (or a bin, but more on that later).
- Each chunk contains a small `metadata header` followed by the `payload` (the actual usable memory returned to the program).
- Chunk metadata includes information such as size, flags (e.g. whether the chunk is in use), and pointers to adjacent chunks if it belongs to a bin.
- Chunks can be in different states: allocated, free, or part of a bin. Free chunks are organized into bins for efficient reuse.
    - Allocated, free, or a part of bin - all these states are from the perspective of the GNU allocator.
    - The OS does not see any individual chunk. Hence allocating and freeing them would not actually allocate/free more memory.
    - Allocated simply means that the chunk is currently owned by the user
    - Free means that the chunk is currently owned by `GLIBC`.
- When a chunk is freed, it may `consolidate` with neighboring free chunks to form a larger chunk and reduce fragmentation.
- A special chunk called the "top chunk" (or "wilderness") exists at the end of the heap segment. It represents the free memory that hasn't been broken into smaller chunks yet.
- When a chunk is requested, `malloc` will try to carve out memory from the wilderness to satisfy the request.

![Desktop View](/assets/img/974ee332b86a74c3ca6246f104105ed3de711781981c3f53845d2eb7cf2e3d95.svg)
_Memory layout of heap and chunks_