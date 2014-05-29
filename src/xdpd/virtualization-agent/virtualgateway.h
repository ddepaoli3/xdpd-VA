/*
 * virtualgateway.h
 *
 *  @author Daniel Depaoli <daniel.depaoli (at) create-net.org>
 */

#include <rofl/common/csocket.h>
#include <string>
#include <pthread.h>

#ifndef VIRTUALGATEWAY_H_
#define VIRTUALGATEWAY_H_

/**
 *
 * UNUSED
 * TO IMPLEMENT
 */

namespace rofl {

class virtualgateway2:
		public csocket_owner,
		public ciosrv
{

private:

		csocket 			*socket;

public:

		/**
		 *
		 */
		virtualgateway2(caddress addr = caddress(AF_INET, "127.0.0.1", 6600));

		/**
		 *
		 */
		virtual void
		handle_accepted(
				csocket *socket,
				int newsd,
				caddress const& ra);

		/**
		 *
		 */
		virtual void
		handle_connected(
				csocket *socket,
				int sd) ;


		/**
		 *
		 */
		virtual void
		handle_connect_refused(
				csocket *socket,
				int sd) ;


		/**
		 *
		 */
		virtual void
		handle_read(
				csocket *socket,
				int sd) ;


		/**
		 *
		 */
		virtual void
		handle_closed(
				csocket *socket,
				int sd) ;

	/**
	 * Read data from socket.
	 *
	 * This notification method is called from within csocket::handle_revent().
	 * A derived class should read a packet from the socket. This method
	 * must be overwritten by a derived class.
	 * @param fd the socket descriptor
	 */
	virtual void
	handle_read(int fd) {
		//WRITELOG(CLI, DBG, "ccli(%p)::handle_read()", this);
	}

	virtual void
	handle_revent(int fd);

protected:


private:
	static void *
	run_terminal(void*);

 	int cli_fd;

	// bound interface
	caddress baddr;

};

} /* namespace rofl */
#endif /* VIRTUALGATEWAY_H_ */
