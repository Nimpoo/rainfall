#include <stdio.h>
#include <sys/time.h>

char c[80];

int m()
{
	time_t v0;

	v0 = time(0);
	return printf("%s - %d\n", c, v0);
}

int main(int argc, const char **argv, const char **envp)
{
	FILE *pass_file_content;
	char **v5;
	char **v6;

	v6 = malloc(8u);
	v6[0] = 1;
	v6[1] = malloc(8u);

	v5 = malloc(8u);
	v5[0] = 2;
	v5[1] = malloc(8u);

	strcpy(v6[1], argv[1]);
	strcpy(v5[1], argv[2]);

	pass_file_content = fopen("/home/user/level8/.pass", "r");
	fgets(c, 68, pass_file_content);
	puts("~~");

	return 0;
}
