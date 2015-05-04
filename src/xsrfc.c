#include <config.h>
#include "xsrfc.h"
#include "xsrf.h"

#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

int xsrfc(struct xsrft* token)
{
	struct sockaddr_un uaddr;
	int sock = 0;

	memset(&uaddr, 0x00, sizeof(struct sockaddr_un));

	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		return -1;
	}

	uaddr.sun_family = AF_UNIX;
	strcpy(uaddr.sun_path, XSRF_SOCK_PATH);

	if (connect(sock, (struct sockaddr*)&uaddr, sizeof(struct sockaddr_un)) == -1) {
		return -1;
	}

	if (send(sock, &(token->val), sizeof(struct xsrft), 0) == -1) {
		close(sock);
		return -1;
	}

	if (recv(sock, &(token->val), sizeof(struct xsrft), 0) < 0) {
		close(sock);
		return -1;
	}

	close(sock);

	if (token->val[0] == (char)0xff) {
		return -2;
	} else if (token->val[0] == (char)0x00) {
		return 0;
	} else {
		return 1;
	}
}

