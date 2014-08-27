#include <config.h>

#ifndef HAVE_FCGI_STDIO_H
#define HAVE_FCGI_STDIO_H 0
#else
#if HAVE_FCGI_STDIO_H
#include <fcgi_stdio.h>
#endif
#endif

#include <stdio.h>

int main()
{
#if HAVE_FCGI_STDIO_H
	while (FCGI_Accept() >= 0) {
#endif
		printf("Content-type: text/html\n\n<!DOCTYPE html>");
		printf("<html><head><title>%s - %s</title></head><body>",
				"OpenWRT SUI", "Advanced Options");

		printf("<h1>%s</h1>", "Advanced Options");

		printf("<p><i>Coming soon...</i></p>");

		printf("<h4><a href=\"/index.cgi\">%s</a></h4>",
				"Basic Options");

		printf("</body></html>");
#if HAVE_FCGI_STDIO_H
	}
#endif

	return 0;
}

