#include <rofl/datapath/hal/cmm.h>
#include <rofl/datapath/hal/openflow/openflow1x/of1x_cmm.h>
#include <rofl/datapath/pipeline/openflow/openflow1x/of1x_switch.h>
#include <rofl/datapath/pipeline/openflow/openflow1x/pipeline/of1x_flow_entry.h>
#include <rofl/datapath/pipeline/physical_switch.h>

#include "management/switch_manager.h"
#include "management/port_manager.h"
#include "management/plugin_manager.h"

#include "virtualization-agent/va_switch.h"
#include "virtualization-agent/virtualagent.h"

using namespace xdpd;

/*
* Dispatching of platform related messages comming from the driver 
*/

hal_result_t hal_cmm_notify_port_add(switch_port_snapshot_t* port_snapshot){
	
	hal_result_t result=HAL_SUCCESS;
	
	if(!port_snapshot)
		return HAL_FAILURE;

	//Notify port manager
	port_manager::__notify_port_added(port_snapshot);

	//Notify attached sw
	if(port_snapshot->is_attached_to_sw)
		//Note that this typecast is valid because hal_result_t and rofl_result_t have intentionally and explicitely the same definition
		result = (hal_result_t)switch_manager::__notify_port_attached((const switch_port_snapshot_t*)port_snapshot);
	
	//Notify MGMT framework
	plugin_manager::__notify_port_added((const switch_port_snapshot_t*)port_snapshot);	

	//Destroy the snapshot
	switch_port_destroy_snapshot(port_snapshot);
		
	return result;
}

hal_result_t hal_cmm_notify_port_delete(switch_port_snapshot_t* port_snapshot){
	
	hal_result_t result = HAL_SUCCESS;
	
	if (!port_snapshot)
		return HAL_FAILURE;

	//Notify port manager
	port_manager::__notify_port_deleted(port_snapshot);

	//Notify attached sw
	if(port_snapshot->is_attached_to_sw)
		//Note that this typecast is valid because hal_result_t and rofl_result_t have intentionally and explicitely the same definition
		result = (hal_result_t)switch_manager::__notify_port_detached((const switch_port_snapshot_t*)port_snapshot);

	//Notify MGMT framework
	plugin_manager::__notify_port_deleted((const switch_port_snapshot_t*)port_snapshot);	

	//Destroy the snapshot
	switch_port_destroy_snapshot(port_snapshot);
	
	return result;
}

hal_result_t hal_cmm_notify_port_status_changed(switch_port_snapshot_t* port_snapshot){
	
	hal_result_t result = HAL_SUCCESS;
	
	if (!port_snapshot)
		return HAL_FAILURE;

	//Notify port manager
	port_manager::__notify_port_status_changed(port_snapshot);

	//Notify attached sw
	if(port_snapshot->is_attached_to_sw)
		//Note that this typecast is valid because hal_result_t and rofl_result_t have intentionally and explicitely the same definition
		result = (hal_result_t)switch_manager::__notify_port_status_changed((const switch_port_snapshot_t*)port_snapshot);

	//Notify MGMT framework
	plugin_manager::__notify_port_status_changed((const switch_port_snapshot_t*)port_snapshot);	

	//Destroy the snapshot
	switch_port_destroy_snapshot(port_snapshot);

	return result;
}

hal_result_t hal_cmm_notify_monitoring_state_changed(monitoring_snapshot_state_t* monitoring_snapshot){

	hal_result_t result = HAL_SUCCESS;
	
	if (!monitoring_snapshot)
		return HAL_FAILURE;

	//Notify MGMT framework
	plugin_manager::__notify_monitoring_state_changed((const monitoring_snapshot_state_t*)monitoring_snapshot);	

	//Destroy the snapshot
	monitoring_destroy_snapshot(monitoring_snapshot);

	return result;
}
/*
* Driver CMM Openflow calls. Demultiplexing to the appropiate openflow_switch instance.
*/ 
hal_result_t hal_cmm_process_of1x_packet_in(uint64_t dpid,
					uint8_t table_id,
					uint8_t reason,
					uint32_t in_port,
					uint32_t buffer_id,
					uint8_t* pkt_buffer,
					uint32_t buf_len,
					uint16_t total_len,
					packet_matches_t* matches){
//	printf("[%s]tipo 0x%x da %" PRIx64 "\n",switch_manager::__get_switch_by_dpid(dpid)->dpname.c_str(),matches->__eth_type, matches->__eth_src);
	if (virtual_agent::is_active())
	{
		va_switch* vaswitch = virtual_agent::list_switch_by_id[dpid];

		std::list<flowspace_struct_t*>::iterator _flowspace; //declaration of single flowspace
		std::list<flowspace_match_t*>::iterator _match;		// declaration of single match
		flowspace_struct_t* tempFlowspace;
		slice* slice = NULL;

		bool matched = false;

		/**
		 * iterate through the flowspaces of the switch
		 */
		for (_flowspace = vaswitch->flowspace_struct_list.begin();
				_flowspace != vaswitch->flowspace_struct_list.end();
				_flowspace++)
		{
			tempFlowspace = *_flowspace;
			if ( vaswitch->check_match(*matches,tempFlowspace->match_list) )
			{
				matched = true;
				slice = vaswitch->get_slice(tempFlowspace->slice);
				break;
			}
		}

		crofctl* controller = NULL;

		if (matched)
		{
			printf("[pack in][%s]Vlan=%i. Slice=%s.",
					switch_manager::__get_switch_by_dpid(dpid)->dpname.c_str(),
					(matches->__has_vlan)?matches->__vlan_vid:0,
					slice->name.c_str());
			controller = virtual_agent::list_switch_by_id[dpid]->controller_map[slice->name];
		}

		if (controller != NULL)
		{
			hal_result_t result = (hal_result_t)switch_manager::__process_of1x_packet_in(dpid, table_id, reason, in_port, buffer_id, pkt_buffer, buf_len, total_len, matches, controller);
			printf("Invio: %s\n", (result)?"ok":"errore");
			return result;
		}
			else
		{
			/**
			 * if no controller was found
			 * return success to not stop.
			 * Packet in is not send.
			 */
			ROFL_ERR("Controller not found. Ignore the packet\n");
			return HAL_SUCCESS;
		}

	}
	else
	{
		//Note that this typecast is valid because hal_result_t and rofl_result_t have intentionally and explicitely the same definition
		return (hal_result_t)switch_manager::__process_of1x_packet_in(dpid, table_id, reason, in_port, buffer_id, pkt_buffer, buf_len, total_len, matches, NULL);
	}
	}

hal_result_t hal_cmm_process_of1x_flow_removed(uint64_t dpid, uint8_t reason, of1x_flow_entry_t* removed_flow_entry){
	//Note that this typecast is valid because hal_result_t and rofl_result_t have intentionally and explicitely the same definition
	return (hal_result_t)switch_manager::__process_of1x_flow_removed(dpid, reason, removed_flow_entry);
}
