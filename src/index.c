#include <stdio.h>

int main()
{
	printf("Content-type: text/html\n\n<!DOCTYPE html>");
	printf("<html><head><title>%s</title></head><body>", "OpenWRT SUI");

	printf("</body></html>");

	return 0;
}

