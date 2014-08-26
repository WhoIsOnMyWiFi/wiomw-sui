#include <stdio.h>

int main()
{
	printf("Content-type: text/html\n\n<!DOCTYPE html>");
	printf("<html><head><title>%s - %s</title></head><body>",
			"OpenWRT SUI", "Advanced Options");

	printf("<h4><a href=\"/index.cgi\">%s</a></h4>", "Basic Options");

	printf("</body></html>");

	return 0;
}

