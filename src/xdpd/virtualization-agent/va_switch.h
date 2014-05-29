/*
 * va_switch.h
 *
 *  @author Daniel Depaoli <daniel.depaoli (at) create-net.org>
 */

#ifndef VA_SWITCH_H_
#define VA_SWITCH_H_

#include "../openflow/openflow_switch.h"
#include "slice.h"
#include "flowspace.h"

class va_switch {
public:

	of_version_t of_switch_vs;
	std::string dp_name ;
	uint64_t dp_id;
	int reconnect_time;
	unsigned int no_table;

	//Port list
	std::list<std::string> port_list;

	// List of slices
	std::list<slice*> slice_list;

	//List of flowspaces
	std::list<flowspace_struct_t*> flowspace_struct_list;

	//Map of controllers instance:
	//[slice]<->[controller]
	std::map<std::string, crofctl*> controller_map;

	//return slice based on controller
	slice* select_slice(crofctl* controller);

	//return slice based on name passed
	slice* get_slice(std::string name);

	//search inside flowspace list a flowspace that correspond with of1x_packet_matches_t
	bool check_match(const packet_matches_t pkt, std::list<flowspace_match_t*> it);


	va_switch();
	va_switch(std::string dp_name ,uint64_t dp_id);
	virtual ~va_switch();

private:

	bool compare_match_flow(const packet_matches_t* pkt, flowspace_match_t* it);
};

#endif /* VA_SWITCH_H_ */
