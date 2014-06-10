/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <rofl/common/utils/c_logger.h>
#include "management/system_manager.h"

using namespace rofl;
using namespace xdpd;

/*
 * xDPd startup routine 
 */
int main(int argc, char** argv){

	ROFL_INFO("\n\n#################################################################\n");
	ROFL_INFO("This version is compiled from a backup code and doesn't work.\nWorking on adapting code to xdpd master\n");
	ROFL_INFO("#################################################################\n\n");
//	exit(EXIT_FAILURE);

	//Check for root privileges 
	if(geteuid() != 0){
		ROFL_ERR("ERROR: Root permissions are required to run %s\n",argv[0]);	
		exit(EXIT_FAILURE);	
	}

	ROFL_INFO("[xdpd] Initializing system...\n");

	//Let system manager initialize all subsytems
	system_manager::init(argc, argv);
	
	ROFL_INFO("[xdpd] Goodbye!\n");
	exit(EXIT_SUCCESS);
}
