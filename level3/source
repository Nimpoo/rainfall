#include <stdio.h>

int m;

int v()
{
	int result;
	char s[520];

	fgets(s, 512, stdin);
	printf(s);
	result = m;
	if (m == 64) {
		fwrite("Wait what?!\n", 1u, 0xCu, stdout);
		return system("/bin/sh");
	}
	return result;
}

int main(int argc, const char **argv, const char **envp)
{
	return v();
}
