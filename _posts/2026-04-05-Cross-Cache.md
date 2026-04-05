---
title: Cross Cache Attacks
date: 2026-04-05 05:30:00 + 0530
categories: [Vulnerability Research, Concepts]
tags: [pwn, kernel, 0-day]     # TAG names should always be lowercase
---

A (Work-In-Progress) writeup for studying Cross-Cache attacks in the Linux kernel SLUB allocator.

---

## Reference Material

### SLUB
- [https://events.static.linuxfound.org/images/stories/pdf/klf2012_kim.pdf](https://events.static.linuxfound.org/images/stories/pdf/klf2012_kim.pdf)
- [https://ruffell.nz/programming/writeups/2019/02/15/looking-at-kmalloc-and-the-slub-memory-allocator.html](https://ruffell.nz/programming/writeups/2019/02/15/looking-at-kmalloc-and-the-slub-memory-allocator.html)
- [https://blogs.oracle.com/linux/linux-slub-allocator-internals-and-debugging-1](https://blogs.oracle.com/linux/linux-slub-allocator-internals-and-debugging-1)
- [https://sam4k.com/linternals-memory-allocators-0x02/](https://sam4k.com/linternals-memory-allocators-0x02/)

### BUDDY
- [https://syst3mfailure.io/linux-page-allocator/](https://syst3mfailure.io/linux-page-allocator/)
- [https://www.geeksforgeeks.org/operating-systems/buddy-system-memory-allocation-technique/](https://www.geeksforgeeks.org/operating-systems/buddy-system-memory-allocation-technique/)

### CROSS-CACHE
- [https://u1f383.github.io/linux/2025/01/03/cross-cache-attack-cheatsheet.html](https://u1f383.github.io/linux/2025/01/03/cross-cache-attack-cheatsheet.html)
- [https://www.usenix.org/system/files/sec23summer_79-lee-prepub.pdf](https://www.usenix.org/system/files/sec23summer_79-lee-prepub.pdf)
- [https://dl.acm.org/doi/10.1145/3719027.3765152](https://dl.acm.org/doi/10.1145/3719027.3765152)
- [https://kaligulaarmblessed.github.io/post/cross-cache-for-lazy-people/](https://kaligulaarmblessed.github.io/post/cross-cache-for-lazy-people/)
- [https://i.blackhat.com/Asia-24/Presentations/Asia-24-Wu-Game-of-Cross-Cache.pdf](https://i.blackhat.com/Asia-24/Presentations/Asia-24-Wu-Game-of-Cross-Cache.pdf)

---

Tested against: [Linux Kernel v6.12](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?h=v6.12).

Source files: [GitHub](https://github.com/VulnX/cross-cache).

---

TODO ... Add writeup
