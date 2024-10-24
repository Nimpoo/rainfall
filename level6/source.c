#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int n()
{
	return system("/bin/cat /home/user/level7/.pass");
}

int m()
{
	return puts("Nope");
}

int main(int argc, const char **argv)
{
	int (**v4)(void);
	char *v5;

	v5 = malloc(0x40u);
	v4 = malloc(4u);
	*v4 = m;
	strcpy(v5, argv[1]);
	return (*v4)();
}
