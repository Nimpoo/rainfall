# rainfall

## _RainFall_ is another `ISO challenge`, and the continuation of the project _[SnowCrash](https://github.com/Nimpoo/snow-crash)_ technically, but instead of exploiting and research the vulnerability of a sytem/user, _RainFall_ is specialized in binary exploitation and reasearch of security breaches in binary files.

All the files to exploit are `ELF binary`. The process is always the same : <br />
1. Test the program <br />
2. Decompilation and/or disassembly <br />
3. Analyse the code <br />
4. Exploit the vulnerability

### Basically, **<u>reverse engineering</u>**.

The reconstruction of the code is a big part of each level : knowing the file you have decomplied AND disassembly, use the right tools, have the right interpretation of the code, and **<u>FIND THE BREACH</u>**.

This project introduces the **exploitation of breaches in files**, **memory manipulation**, running **arbritrary code** and the <u>importance of how a program must be protected</u>. All the exploits on these levels are classic, but some are very tricky and can breaks your mind. By far, _RainFall_ is better than _SnowCrash_, but not really funnier to do, you need to learn a lot of things about _How a machhine works_, or even _How the `assembly` works_ :

### **It's a very enriching project**.

_RainFall_ can also be an introduction of the language **ASM** (Assembly) if you never used it before. Sometimes, read the desassembly of a file can be very useful to understand the code and find the breach. After finishing this project and _[OverRide](https://github.com/Nimpoo/override)_, continuing with _[libasm](https://github.com/Nimpoo/libasm)_ is not a bad idea if the language `ASM` is interesting you.

I write this `README.md` after having resolve all the levels with my bro [Noah](https://github.com/noalexan). Even than _SnowCrash_, each level documents the steps I took to solve the challenge, the tools I used, and even the mistakes I made. I aim to transcribe my logic, and my research, and it's more technical than the previous project.

# Virtual Machine Setup

The subject give to us a pdf file with all rules of the project. And an image disk that we have to run with. Personally, I use qemu to run it. But you can use VirtualBox or VMware if you want.

You can view my script to run the virtual machine [here](assets/run.sh).

Just after that, I can connect to my machine with the following command:

```sh
➜  ~ ssh level0@127.0.0.1 -p 4242
```

And for get the files from the virtual machine, I use scp:

```sh
➜  ~ scp -P 4242 level0@127.0.0.1:/home/user/level0/level0 /Users/mayoub/Desktop
```

# _<u>🚨 SPOILER ZONE 🚨</u>_

## Summary from `level0` to `level9` :
- [`level0`](./level0/walkthrough.md) : Introduction to <u>decompilation</u> and <u>disassembly</u>
- [`level1`](./level1/walkthrough.md) : **Stack-Based** Buffer Overflow - Basic
- [`level2`](./level2/walkthrough.md) : **Stack-Based** Buffer Overflow - `Ret2Libc`
- [`level3`](./level3/walkthrough.md) : **Format String** Vulnerability - 1st method (using `python`)
- [`level4`](./level4/walkthrough.md) : **Format String** Vulnerability - 2nd method (using `%x` and `spaces`)
- [`level5`](./level5/walkthrough.md) : **Format String** Vulnerability - `PLT` overwriting
- [`level6`](./level6/walkthrough.md) : **Heap-Based** Buffer Overflow - Basic
- [`level7`](./level7/walkthrough.md) : **Heap-Based** Buffer Overflow - `PLT` overwriting
- [`level8`](./level8/walkthrough.md) : **Breach Exploitation** and **Memory Manipulation** by understanding a decompiled program 
- [`level9`](./level9/walkthrough.ms) : **Shellcode Injection** and **Memory Manipulation** of a binary programmed in **`C++`**

## Summary from `bonus0` to `bonus3` :
- [`bonus0`](./bonus0/walkthrough.md) : **Shellcode Injection** by `environment variables` and **Stack-Based** Buffer Overflow
- [`bonus1`](./bonus1/walkthrough.md) : **Integer Overflow** Attack and **Stack-Based** Buffer Overflow
- [`bonus2`](./bonus2/walkthrough.md) : **Shellcode Injection** by `environment variables` and **Stack-Based** Buffer Overflow
- [`bonus3`](./bonus3/walkthrough.md) : **Breach Exploitation** (This level is a joke ?)

<br />

![Garp](assets/Garp.gif)
