#include <stdint.h>

int language;
__uint128_t xmmword_8048717 = ((__uint128_t)0xC3A4C37669A4C370ULL << 64) | 0x20A4C3A4C3767948ULL;

int greetuser(char src)
{
  __uint128_t dest;
  int v3;
  char v4;

  switch ( language )
  {
    case 1:
      dest = xmmword_8048717;
      v3 = *((int *)&xmmword_8048717 + 8);
      v4 = *((char *)&xmmword_8048717 + 18);
      break;
    case 2:
      strcpy((char *)&dest, "Goedemiddag! ");
      break;
    case 0:
      strcpy((char *)&dest, "Hello ");
      break;
  }
  strcat((char *)&dest, &src);
  return puts((const char *)&dest);
}

int main(int argc, char **argv)
{
  char v4[76];
  char dest[76];
  char *v6;

  if ( argc != 3 )
    return 1;
  memset(dest, 0, sizeof(dest));
  strncpy(dest, argv[1], 40);
  strncpy(&dest[40], argv[2], 32);
  v6 = getenv("LANG");
  if ( v6 )
  {
    if ( !memcmp(v6, "fi", 2) )
    {
      language = 1;
    }
    else if ( !memcmp(v6, "nl", 2) )
    {
      language = 2;
    }
  }
  qmemcpy(v4, dest, sizeof(v4));
  return greetuser(v4[0]);
}