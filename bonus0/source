#include <string.h>

char *p(char *dest, char *s)
{
	char buf[4104];

	puts(s);
	read(0, buf, 0x1000u);
	*strchr(buf, 10) = 0;
	return strncpy(dest, buf, 0x14u);
}

char *pp(char *dest)
{
	char src[20];
	char v3[28];

	p(src, " - ");
	p(v3, " - ");
	strcpy(dest, src);
	size_t len = strlen(dest);
  dest[len - 1] = ' ';
  dest[len] = 0;
	return strcat(dest, v3);
}

int main(int argc, const char **argv, const char **envp)
{
	char s[42];

	pp(s);
	puts(s);
	return 0;
}
