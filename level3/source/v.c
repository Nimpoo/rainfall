// Ghidra

#include <stdio.h>

int m; // ? global variale : we can't see it with Ghidra, but the decompiler "Hex-Rays" can see it

void v(void)

{
  char local_20c [520];
  
  fgets(local_20c,0x200,stdin);
  printf(local_20c);
  if (m == 0x40) { // * 0x40 = 64
    fwrite("Wait what?!\n",1,0xc,stdout);
    system("/bin/sh");
  }
  return;
}