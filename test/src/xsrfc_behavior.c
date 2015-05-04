#include <config.h>
#include <dejagnu.h>

#include "../../src/b2h.h"
#include "../../src/xsrf.h"
#include "../../src/xsrfc.h"

void test_xsrfc_happy_path()
{
	struct xsrft token;
	int res = 0;
	char hextoken[XSRF_TOKEN_HEX_LENGTH];

	note("running test_xsrfc_happy_path");

	memset(&token, 0x00, sizeof(struct xsrft));

	if ((res = xsrfc(&token)) < 0) {
		fail("error during initial xsrfc call");
	} else if (token.val[0] == 0xff || token.val[0] == 0x00 || res == 0) {
		fail("initial xsrfc call returned bad token");
	} else {
		pass("initial xsrfc call succeeded");
	}

	note("token is: %s", token.val);
	b2h(hextoken, token.val, XSRF_TOKEN_BINARY_LENGTH);
	note("double hex token is: %s", hextoken);

	if ((res = xsrfc(&token)) < 0) {
		fail("error during second xsrfc call");
	} else if (token.val[0] == 0xff || token.val[0] == 0x00 || res == 0) {
		fail("second xsrfc call returned bad token");
	} else {
		pass("second xsrfc call succeeded");
	}
	
	note("token is: %s", token.val);
	b2h(hextoken, token.val, XSRF_TOKEN_BINARY_LENGTH);
	note("double hex token is: %s", hextoken);

	if ((res = xsrfc(&token)) < 0) {
		fail("error during third xsrfc call");
	} else if (token.val[0] == 0xff || token.val[0] == 0x00 || res == 0) {
		fail("third xsrfc call returned bad token");
	} else {
		pass("third xsrfc call succeeded");
	}

	note("token is: %s", token.val);
	b2h(hextoken, token.val, XSRF_TOKEN_BINARY_LENGTH);
	note("double hex token is: %s", hextoken);

	token.val[0] = (token.val[0] == 'A')? 'B' : 'A';

	note("token is: %s", token.val);
	b2h(hextoken, token.val, XSRF_TOKEN_BINARY_LENGTH);
	note("double hex token is: %s", hextoken);

	if ((res = xsrfc(&token)) < 0) {
		fail("error during fourth xsrfc call");
	} else if (token.val[0] == 0xff || token.val[0] == 0x00 || res == 0) {
		pass("fourth xsrfc call returned bad token");
	} else {
		fail("fourth xsrfc call succeeded");
	}

	note("token is: %s", token.val);
	b2h(hextoken, token.val, XSRF_TOKEN_BINARY_LENGTH);
	note("double hex token is: %s", hextoken);
}

int main()
{
	test_xsrfc_happy_path();

	return 0;
}

