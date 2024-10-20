#include <stdio.h>
#include <stdlib.h>
#include <string.h>

class N
{
private:
	char buffer[104];
	int value;
public:

	N(int value)
	{
		this->value = value;
	}

	int operator+(N number)
	{
		return this->value + number.value;
	}

	int operator-(N number)
	{
		return this->value - number.value;
	}

	void setAnnotation(char *str)
	{
		memcpy(this->buffer, str, strlen(str));
	}
};

int main(int argc, char **argv)
{
	if (argc < 2) {
		exit(1);
	}

	N *first = new N(5);
	N *second = new N(6);

	first->setAnnotation(argv[1]);

	return (*first + *second);
}
