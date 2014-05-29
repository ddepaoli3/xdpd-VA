/*
 * virtualgateway.cpp
 *
 *  @author Daniel Depaoli <daniel.depaoli (at) create-net.org>
 */

#include "virtualgateway.h"
#include <rofl/common/csocket.h>
#include "../openflow/openflow_switch.h"

/**
 *
 * UNUSED
 * TO IMPLEMENT
 */

namespace rofl {
//virtualgateway2::virtualgateway2(caddress addr):
//				socket(new csocket(this, PF_INET, SOCK_STREAM, IPPROTO_TCP, 10)),
//				cli_fd(-1),
//				baddr(addr)
//{
//	printf("Listen to virtual gateway\n");
//	socket->clisten(baddr, PF_INET, SOCK_STREAM, IPPROTO_TCP);
//}


void virtualgateway2::handle_accepted(csocket* socket, int newsd,
		const caddress& ra) {
	//int fd = socket->getfd();
	char buffer[256];
	bzero(buffer, 256);
	int n = read(newsd, buffer, 255);
	printf("Message: %s %i\n", buffer, n);

	//socket->cclose();
}

void virtualgateway2::handle_connected(csocket* socket, int sd) {
	printf("Connected\n");
}

void virtualgateway2::handle_connect_refused(csocket* socket, int sd) {
	printf("Reject\n");
}

void virtualgateway2::handle_read(csocket* socket, int sd) {
	printf("read\n");
}

void virtualgateway2::handle_closed(csocket* socket, int sd) {
	printf("close\n");
}

void virtualgateway2::handle_revent(int fd) {
	printf("handle_revent");
}


}


