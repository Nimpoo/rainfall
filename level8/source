#include <stdbool.h>
#include <stdio.h>

char *auth;
char *service;

int main()
{
	char s[5];
	char v5[2];
	char v6[129];

	while (true) {
		printf("%p, %p \n", auth, service);

		if (!fgets(s, 128, stdin))
			break;

		if (!memcmp(s, "auth ", 5u)) {
			auth = malloc(4u);
			*auth = 0;
			if (strlen(v5) <= 30)
				strcpy(auth, v5);
		}

		if (!memcmp(s, "reset", 5u))
			free(auth);

		if (!memcmp(s, "service", 6u))
			service = strdup(v6);

		if (!memcmp(s, "login", 5u)) {
			if (auth[8])
				system("/bin/sh");
			else
				fwrite("Password:\n", 1u, 10u, stdout);
		}
	}

	return 0;
}
