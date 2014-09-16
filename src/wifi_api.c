#include <config.h>

#ifndef HAVE_FCGI_STDIO_H
#define HAVE_FCGI_STDIO_H 0
#else
#if HAVE_FCGI_STDIO_H
#include <fcgi_stdio.h>
#endif
#endif

#include <stdio.h>
#include <ctype.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>

void print_post_data()
{
	char c = '\0';
	printf("<code>");
	while ((c = getchar()) != EOF) {
		printf("&#x%02X;", c);
	}
	printf("</code>");
}

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

void save_ssid_form(char** essid, char** psk)
{
	char c = '\0';
	char buffer[BUFSIZ];
	size_t len = 0;
	unsigned char state = 0;
	while ((c = getc(stdin)) != EOF) {
		switch (state) {
		case 0:
			if (c == 'e') {
				state = 2;
			} else if (c == 'p') {
				state = 3;
			} else if (c != '&') {
				state = 1;
			}
			break;
		case 1:
			if (c == '&') {
				state = 0;
			}
			break;
		case 2:
			if (c != 's' || (c = getc(stdin)) != 's'
					|| (c = getc(stdin)) != 'i'
					|| (c = getc(stdin)) != 'd'
					|| (c = getc(stdin)) != '=') {
				ungetc(c, stdin);
				state = 1;
			} else {
				state = 4;
			}
			break;
		case 3:
			if (c != 's' || (c = getc(stdin)) != 'k'
					|| (c = getc(stdin)) != '=') {
				ungetc(c, stdin);
				state = 1;
			} else {
				state = 5;
			}
			break;
		case 4:
			do {
				char c1 = '\0';
				if (c == '+') {
					buffer[len++] = ' ';
				} else if (c != '%') {
					buffer[len++] = c;
				} else if (!isxdigit(c1 = getc(stdin))) {
					return;
				} else if (!isxdigit(c = getc(stdin))) {
					return;
				} else {
					if (isdigit(c1)) {
						buffer[len] = 0xF0 & ((c1 - '0') << 4);
					} else {
						buffer[len] = 0xF0 & ((toupper(c1) - 'A' + 0x0A) << 4);
					}
					if (isdigit(c)) {
						buffer[len] |= 0x0F & (c - '0');
					} else {
						buffer[len] |= 0x0F & (toupper(c) - 'A' + 0x0A);
					}
					len++;
				}
			} while ((c = getc(stdin)) != '&' && c != EOF);
			if (len > 0) {
				if (*essid != NULL) {
					free(*essid);
				}
				buffer[len] = '\0';
				*essid = strdup(buffer);
				len = 0;
			}
			state = 0;
			ungetc(c, stdin);
			break;
		case 5:
			do {
				char c1 = '\0';
				if (c == '+') {
					buffer[len++] = ' ';
				} else if (c != '%') {
					buffer[len++] = c;
				} else if (!isxdigit(c1 = getc(stdin))) {
					return;
				} else if (!isxdigit(c = getc(stdin))) {
					return;
				} else {
					if (isdigit(c1)) {
						buffer[len] = 0xF0 & ((c1 - '0') << 4);
					} else {
						buffer[len] = 0xF0 & ((toupper(c1) - 'A' + 0x0A) << 4);
					}
					if (isdigit(c)) {
						buffer[len] |= 0x0F & (c - '0');
					} else {
						buffer[len] |= 0x0F & (toupper(c) - 'A' + 0x0A);
					}
					len++;
				}
			} while ((c = getc(stdin)) != '&' && c != EOF);
			if (len > 0) {
				if (*psk != NULL) {
					free(*psk);
				}
				buffer[len] = '\0';
				*psk = strdup(buffer);
				len = 0;
			}
			state = 0;
			ungetc(c, stdin);
			break;
		}
	}

}

void print_ssid_form(const char* essid, const char* psk)
{
	printf("<form action=\"/index.cgi\" method=\"POST\">");
	printf("<fieldset><legend>%s</legend>", "Who Is On My WiFi Login");
	printf("<table><tr>");
	printf("<td>%s</td><td><input type=\"text\" name=\"essid\"",
			"WiFi AP Name");
	if (essid != NULL) {
		size_t i = 0;
		printf(" value=\"");
		for (i = 0; essid[i] != '\0'; i++) {
			printf("&#x%02X;", essid[i]);
		}
		printf("\"");
	}
	printf(" /></td></tr><tr>");
	printf("<td>%s</td><td><input type=\"text\" name=\"psk\"",
			"WiFi Password");
	if (psk != NULL) {
		size_t i = 0;
		printf(" value=\"");
		for (i = 0; psk[i] != '\0'; i++) {
			printf("&#x%02X;", psk[i]);
		}
		printf("\"");
	}
	printf(" /></td></tr></table><input type=\"submit\" value=\"%s\" />",
			"Save");
	printf("</fieldset></form>");
}

int main()
{
	char* method = NULL;

	char* essid = NULL;
	char* psk = NULL;

#if HAVE_FCGI_STDIO_H
	while (FCGI_Accept() >= 0) {
#endif
		printf("Content-type: text/html\n\n<!DOCTYPE html>");
		printf("<html><head><title>%s</title></head><body>",
				"OpenWRT SUI");

		printf("<h1>%s</h1>", "Basic Options");

		method = getenv("REQUEST_METHOD");
		if (method == NULL) {
			printf("<h3>No method provided</h3>");
		} else if (strcmp(method, "POST") == 0) {
			printf("<h3>Getting post data</h3>");
			save_ssid_form(&essid, &psk);
			rewind(stdin);
			print_post_data();
		} else {
			printf("<h3>Got method: %s</h3>", method);
		}


		print_wiomw_login_form();

		print_ssid_form(essid, psk);

		printf("<h4><a href=\"/advanced.cgi\">%s</a></h4>",
				"Advanced Options");

		printf("</body></html>");
#if HAVE_FCGI_STDIO_H
	}
#endif

	return 0;
}

