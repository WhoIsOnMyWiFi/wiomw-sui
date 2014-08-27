#include <config.h>

#ifndef HAVE_FCGI_STDIO_H
#define HAVE_FCGI_STDIO_H 0
#else
#if HAVE_FCGI_STDIO_H
#include <fcgi_stdio.h>
#endif
#endif

#include <stdio.h>

void print_wiomw_login_form()
{
	char* old_username = "";

	printf("<form action=\"/index.cgi\" method=\"POST\">");
	printf("<fieldset><legend>%s</legend>", "Who Is On My WiFi Login");
	printf("<table><tr>");
	printf("<td>%s</td><td><input type=\"text\" name=\"username\">",
			"Username");
	printf("%s</input></td></tr><tr>", old_username);
	printf("<td>%s</td><td><input type=\"password\" name=\"password\" />",
			"Password");
	printf("</td></tr></table><input type=\"submit\" value=\"%s\" />",
			"Login");
	printf("</fieldset></form>");
}

int main()
{
#if HAVE_FCGI_STDIO_H
	while (FCGI_Accept() >= 0) {
#endif
		printf("Content-type: text/html\n\n<!DOCTYPE html>");
		printf("<html><head><title>%s</title></head><body>",
				"OpenWRT SUI");

		printf("<h1>%s</h1>", "Basic Options");

		print_wiomw_login_form();

		printf("<h4><a href=\"/advanced.cgi\">%s</a></h4>",
				"Advanced Options");

		printf("</body></html>");
#if HAVE_FCGI_STDIO_H
	}
#endif

	return 0;
}

