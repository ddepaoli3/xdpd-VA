#include "openflow_switch.h"

using namespace rofl;
using namespace xdpd;

openflow_switch::openflow_switch(const uint64_t dpid, const std::string &dpname, const of_version_t version, unsigned int num_of_tables) :
		endpoint(NULL),
		dpid(dpid),
		dpname(dpname),
		version(version),
		num_of_tables(num_of_tables)
{

}

/*
* Port notfications. Process them directly in the endpoint
*/
rofl_result_t openflow_switch::notify_port_attached(const switch_port_t* port){
	this->port_list.push_back(port->name);
	return endpoint->notify_port_attached(port);
}
rofl_result_t openflow_switch::notify_port_detached(const switch_port_t* port){
	return endpoint->notify_port_detached(port);
}
rofl_result_t openflow_switch::notify_port_status_changed(const switch_port_t* port){
	return endpoint->notify_port_status_changed(port);
}


/*
* Connecting and disconnecting from a controller entity
*/
void openflow_switch::rpc_connect_to_ctl(enum rofl::csocket::socket_type_t socket_type, cparams const& socket_params){
	rofl::openflow::cofhello_elem_versionbitmap versionbitmap;
	versionbitmap.add_ofp_version(version);
	endpoint->rpc_connect_to_ctl(versionbitmap, 0, socket_type, socket_params);
}

void openflow_switch::rpc_disconnect_from_ctl(enum rofl::csocket::socket_type_t socket_type, cparams const& socket_params){
	//endpoint->rpc_disconnect_from_ctl(socket_type, socket_params);
}


bool openflow_switch::port_is_present(std::string port) {
	std::vector<std::string>::iterator port_iter;
	for (port_iter = this->port_list.begin();
			port_iter != this->port_list.end();
			port_iter++)
	{
		const char *string1 = port.c_str();
		const char *string2 = port_iter->c_str();
		if ( strcmp(string1, string2) == 0 )
			return true;
	}
return false;
}

std::string openflow_switch::num_to_port(uint64_t num) {
	if (num <= this->port_list.size() )
		return this->port_list[num-1];
	else
		return "NULL";
}

uint16_t openflow_switch::port_to_num(std::string port_name) {

	std::vector<std::string>::iterator port_iter;
	uint16_t count = 0;
	for (port_iter = this->port_list.begin();
			port_iter != this->port_list.end();
			port_iter++)
	{
		count++;
		if (port_name.compare(port_iter->c_str())==0)
			return count;
	}
	return 0;
}


