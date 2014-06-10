#include "root_scope.h"
#include <rofl/platform/unix/cunixenv.h>
#include <rofl/common/utils/c_logger.h>

//sub scopes
#include "openflow/openflow_scope.h" 
#include "interfaces/interfaces_scope.h" 
#include "system/system_scope.h" 

#include "virtualization-agent/flowspace_scope.h"
#include "virtualization-agent/virtual-agent_scope.h"
#include "virtualization-agent/slice_scope.h"
#include "../../../virtualization-agent/virtualagent.h"

using namespace xdpd;
using namespace rofl;
using namespace libconfig; 

root_scope::root_scope():scope("root"){
	//config subhierarchy
	register_subscope(new config_scope());

	if (virtual_agent::is_active()) {

		ROFL_INFO("Register virtualization option\n");

		//Register Slice scope
		register_subscope(new root_slice_scope());

		//Register Flowspace
		register_subscope(new root_flowspace_scope());

		//Virtual Agent interface
		register_subscope(new virtual_agent_scope("virtual-agent", false));
	}
	else
		ROFL_INFO("Virtualization is deactivate\n");
}

root_scope::~root_scope(){
	//Remove all objects
}

config_scope::config_scope():scope("config", true){

	//Openflow subhierarchy
	register_subscope(new openflow_scope());
	
	//Interfaces subhierarchy
	register_subscope(new interfaces_scope());	
	
	//System subhierarchy
	register_subscope(new system_scope());	
}

config_scope::~config_scope(){
	//Remove all objects
}

/**
 * Virtualization part
 */
root_slice_scope::root_slice_scope(std::string name, bool mandatory):scope(name, mandatory){

	//Register subscopes
	//Slice subscope elements will be captured on pre_validate hook

}

void root_slice_scope::pre_validate(libconfig::Setting& setting, bool dry_run){

	if(setting.getLength() == 0){
		ROFL_ERR("%s: No slices found!\n", setting.getPath().c_str());
		throw eConfParseError();

	}
	//Detect existing subscopes (logical switches) and register
	if (setting.getLength() == 0)
	{
		ROFL_ERR("No slice found. Impossible to continue\n");
		throw eConfParseError();
	}
 	for(int i = 0; i<setting.getLength(); ++i){
		ROFL_DEBUG_VERBOSE("Found slice: %s\n", setting[i].getName());
		register_subscope(std::string(setting[i].getName()), new slice_scope(setting[i].getName()));
	}

}

root_flowspace_scope::root_flowspace_scope(std::string name, bool mandatory):scope(name, mandatory){

	//Register subscopes
	//Subscopes are logical switch elements so will be captured on pre_validate hook

}

void root_flowspace_scope::pre_validate(libconfig::Setting& setting, bool dry_run){

	if(setting.getLength() == 0){
		ROFL_ERR("%s: No flowspace found!\n", setting.getPath().c_str());
		throw eConfParseError();
	}

	//Detect existing subscopes (logical switches) and register
 	for(int i = 0; i<setting.getLength(); ++i){
		ROFL_DEBUG_VERBOSE("Found flowspace: %s\n", setting[i].getName());
		register_subscope(std::string(setting[i].getName()), new flowspace_scope(setting[i].getName()));
	}

}
