/*
 * slice.h
 *
 *
 *  @author Daniel Depaoli <daniel.depaoli (at) create-net.org>
 */

#ifndef XDPDCLASS_H_
#define XDPDCLASS_H_

#include "../openflow/openflow_switch.h"
using namespace std;


//namespace xdpd {

class slice {
public:

	std::string dp_name ;
	uint64_t dp_id;
	caddress address;
	std::string name;
	std::vector<std::string> ports_list;

	// Slice id set by virtual agent
	uint32_t slice_id;

	virtual ~slice();

	slice(std::string dp_name, uint64_t dp_id, std::string name, caddress address, std::vector<std::string> ports_list);

	slice(caddress address);

	uint64_t getDpId() const {
		return dp_id;
	}

	const std::string& getDpName() const {
		return dp_name;
	}

	bool has_port(std::string port_name);

};

//}
#endif /* XDPDCLASS_H_ */
