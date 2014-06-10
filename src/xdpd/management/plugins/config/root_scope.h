#ifndef ROOT_SCOPE_H
#define ROOT_SCOPE_H 

#include <iostream>
#include <libconfig.h++> 
#include <rofl/common/croflexception.h>
#include "scope.h"

/**
* @file root_scope.h
* @author Marc Sune<marc.sune (at) bisdn.de>
*
* @brief Root node of the configuration 
* 
*/

namespace xdpd {

class root_scope : public scope {
	
public:
	root_scope();
	virtual ~root_scope();
		
private:

};

class config_scope : public scope {
	
public:
	config_scope();
	virtual ~config_scope();
		
private:

};

/**
 * @author Daniel Depaoli <daniel.depaoli (at) create-net.org>
 * Slice and flowspace class settings
 *
 * Class and methods follow default xdpd configuration
 */
class root_slice_scope:public scope {

public:
	root_slice_scope(std::string scope_name="slice", bool mandatory=false);

protected:

	virtual void pre_validate(libconfig::Setting& setting, bool dry_run);
};

class root_flowspace_scope:public scope {

public:
	root_flowspace_scope(std::string scope_name="flowspace", bool mandatory=false);

protected:

	virtual void pre_validate(libconfig::Setting& setting, bool dry_run);
};



}// namespace xdpd 

#endif /* ROOT_SCOPE_H_ */


