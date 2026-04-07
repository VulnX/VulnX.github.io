---
title: PWN cheatsheet
date: '2024-08-27T08:30:00+05:30'
event: Blog Post
category: misc
difficulty: Intermediate
author:
- VulnX
tags:
- pwn
description: '> I will keep updating this as and when I learn more. {: .prompttip
  }  > I assume you are already familiar and comfortable with the linux ecosystem
  an...'
---
> I will keep updating this as and when I learn more.
{: .prompt-tip }

> I assume you are already familiar and comfortable with the linux ecosystem and the CLI.<br>
> If not, get yourself familiar :D
{: .prompt-info }

When I started my journey in learning binary exploitation, I found it difficult to find good quality free resources. Here I plan to compile a list of resources which would have been just apt for me to get started.

# Basics

Binary exploitation is a vast and very complicated thing. I often find sticking to the basic simple concepts more helpful.

## Learn C/C++

Python, Java, Rust, Go and all are great but when dealing with such low level concepts its advisable to have a solid understanding of C/C++

The goal isn't to become an absolute master in C but to have a decent enough understanding such that, given enough time and resources you are able to write solutions no matter how complex the problem is.

### RESOURCES

1. [Computer Science - Crash Course](https://youtube.com/playlist?list=PL8dPuuaLjXtNlUrzyH5r6jN9ulIgZBpdo&si=da0TXgtYqKC7S9b7)
2. [https://www.learn-c.org/](https://www.learn-c.org/)

## Pointers and memory

Focus on pointer and how data structures are implemented in memory. Try automatically common tasks by writing the solution in C and test your skills. Start using the GLIBC functions extensively, purely for the sake of exposure.

### RESOURCES

1. [Understanding Pointers](https://github.com/jflaherty/ptrtut13/)
2. [Another fun video for complex pointer syntax](https://youtu.be/qclZUQYZTzg?si=bV2vJmo7k1b8-Ezo)
3. [Clockwise Spiral Rule - Useful for breaking down complex pointer expression (if understood)](https://c-faq.com/decl/spiral.anderson.html)

## Assembly

Having a good understanding of assembly is very benefical in reverse engineering. But it is also a very satisfying process.

## RESOURCES

1. [x86 course](https://0xinfection.github.io/reversing/pages/x86-course.html)
2. [asmtutor](https://asmtutor.com)
3. [awesome-asm 😅](https://github.com/VulnX/awesome-asm)
4. [x86 & amd64 instruction set (unofficial, but great!)](https://www.felixcloutier.com/x86)
5. [Exercism x86-64](https://exercism.org/tracks/x86-64-assembly)

Although x86 is still useful, but 32-bit systems are comparatively rare now. It's better if you focus more on x86-64 assembly. But mostly the concepts remain same.

Don't rush into things. Always remember, learning these low level concepts isn't a prerequisite for pwning, but rather a part of it.

# Reverse Engineering

I strongly believe that this section deserves a separate post but for now since I have limited resources, let it be.

Start by having a good understanding of assembly and how various structures are implemented in memory.

Start writing basic programs in C and then use `objdump` on the compiled binary to view its disassembly. From the disassembly try to honestly come up with a psuedo C code and see how well it matches. Keep doing this over and over until you start seeing patterns and eventually things just start to make sense.

For bigger or more complex problems, don't hesitate to use a decompiler like [ghidra](https://ghidra-sre.org/).

Best way to advance your skills is by solving different types of challenges. Checkout [crackmes.one](https://crackmes.one/)

# Binary exploitation

## 💎 **pwn.college**

pwn college is without doubt one of the most excellent free cyber security resource you can find on the internet. I highly recommend using this for learning pwn and some reverse engineering.

## RESOURCES

| [pwn.college](https://pwn.college)                                                                    | GOLDMINE pwn content                                                                                                                 |
| ---------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| [pwnable.kr](https://pwnable.kr)                                                                     | Wargame site                                                                                                                         |
| [exploit.education](https://exploit.education)                                                       | Courses related to bin ex                                                                                                            |
| [LiveOverflow](https://www.youtube.com/playlist?app=desktop&list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN) | Great YT playlist. Slightly outdated now but still worth watching                                                                    |
| [ir0nstone gitbook](https://ir0nstone.gitbook.io/notes)                                              | A very good compilation of several different types of attack techniques.<br>You can use this as a checklist to learn them            |
| [how2heap](https://github.com/shellphish/how2heap)                                                   | Best way to study various heap exploits                                                                                              |
| [Dhaval Kapil GitBook](https://heap-exploitation.dhavalkapil.com/)                                   | Another nice resource to learn heap exploitation                                                                                     |
| [radare2 cheatsheet](https://r2wiki.readthedocs.io/en/latest/home/misc/cheatsheet/)                  | Radare2 is an impressively powerful debugger,<br>although admittedly with steep learning curve                                       |
| [pwntools cheatsheet](https://gist.github.com/anvbis/64907e4f90974c4bdd930baeb705dedf)               | Absolutely goated python module for exploit development.<br>Ensure to read the docs to utilise it to its full potential              |
| [pwndbg cheatsheet](https://drive.google.com/file/d/16t9MV8KTFXK7oX_CzXhmDdaVnjT8IYM4/view)           | If you use GDB, you should 100% be using pwndbg for a better experience.<br>Use this official cheatsheet to utilise its capabilities |


