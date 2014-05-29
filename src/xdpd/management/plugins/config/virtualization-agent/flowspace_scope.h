/*
 * flowspace_scope.h
 *
 *  @author Daniel Depaoli <daniel.depaoli (at) create-net.org>
 */

#ifndef FLOWSPACE_SCOPE_H_
#define FLOWSPACE_SCOPE_H_

#include "../scope.h"
#include  "../../../../virtualization-agent/flowspace.h"

namespace xdpd {


class flowspace_scope: public xdpd::scope {
public:
	flowspace_scope(std::string scope_name="flowspace", bool mandatory=true);
	virtual ~flowspace_scope();

protected:
	virtual void post_validate(libconfig::Setting& setting, bool dry_run);
	void validate_flowspace_registration(libconfig::Setting& setting, bool dry_run, flowspace_struct_t* flowspaceStruct);
};

}

#endif /* FLOWSPACE_SCOPE_H_ */
