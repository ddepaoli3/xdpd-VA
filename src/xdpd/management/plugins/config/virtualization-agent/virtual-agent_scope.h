#ifndef CONFIG_VIRTUALAGENT_PLUGIN_H
#define CONFIG_VIRTUALAGENT_PLUGIN_H

#include "../scope.h"


namespace xdpd {

class virtual_agent_scope:public scope {
	
public:
	virtual_agent_scope(std::string scope_name="virtual-agent", bool mandatory=true);
		
protected:
	virtual void post_validate(libconfig::Setting& setting, bool dry_run);
	virtual void pre_validate(libconfig::Setting& setting, bool dry_run);
	
};

}// namespace xdpd 

#endif /* CONFIG_VIRTUALAGENT_PLUGIN_H_ */


