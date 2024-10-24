#include <stdio.h>
#include <stdlib.h>

int m;

int p(char *format)
{
	return printf(format);
}

int n()
{
	int result;
	char s[520];

	fgets(s, 512, stdin);
	p(s);
	result = m;
	if (m == 16930116)
		return system("/bin/cat /home/user/level5/.pass");
	return result;
}

int main()
{
	return n();
}
