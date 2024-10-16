// Ghidra

#include <stdio.h>

int m; // ? global variale : we can't see it with Ghidra, but the decompiler "Hex-Rays" can see it

void n(void)

{
  char local_20c [520];
  
  fgets(local_20c,0x200,stdin);
  p(local_20c);
  if (m == 0x1025544) { // * 0x1025544 = 16930116
    system("/bin/cat /home/user/level5/.pass");
  }
  return;
}