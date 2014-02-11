/*
 * @section LICENSE
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 * 
 * @author: msune, akoepsel, tjungel, valvarez, 
 * 
 * @section DESCRIPTION 
 * 
 * GNU/Linux forwarding_module dispatching routines. This file contains primary AFA driver hooks
 * for CMM to call forwarding module specific functions (e.g. bring up port, or create logical switch).
 * Openflow version dependant hooks are under openflow/ folder. 
*/


#include <stdio.h>
#include <rofl/datapath/afa/fwd_module.h>
#include <rofl/common/utils/c_logger.h>
#include <rofl/datapath/afa/cmm.h>
#include <rofl/datapath/pipeline/platform/memory.h>
#include <rofl/datapath/pipeline/physical_switch.h>
#include <rofl/datapath/pipeline/openflow/openflow1x/of1x_switch.h>
#include "../processing/processingmanager.h"
#include "../io/bufferpool.h"
#include "../io/iomanager.h"
#include "../bg_taskmanager.h"

#include "../io/iface_utils.h"
#include "../processing/ls_internal_state.h"

//only for Test
#include <stdlib.h>
#include <string.h>
#include <rofl/datapath/pipeline/openflow/of_switch.h>
#include <rofl/datapath/pipeline/common/datapacket.h>

using namespace xdpd::gnu_linux;

/*
* @name    fwd_module_init
* @brief   Initializes driver. Before using the AFA_DRIVER routines, higher layers must allow driver to initialize itself
* @ingroup fwd_module_management
*/
afa_result_t fwd_module_init(){

	ROFL_INFO(FWD_MOD_NAME" Initializing forwarding module...\n");
	
	//Init the ROFL-PIPELINE phyisical switch
	if(physical_switch_init() != ROFL_SUCCESS)
		return AFA_FAILURE;
	

	//create bufferpool
	bufferpool::init();

	if(discover_physical_ports() != ROFL_SUCCESS)
		return AFA_FAILURE;

	//Initialize the iomanager
	iomanager::init();

	//Initialize Background Tasks Manager
	if(launch_background_tasks_manager() != ROFL_SUCCESS){
		return AFA_FAILURE;
	}
	
	return AFA_SUCCESS; 
}

/*
* @name    fwd_module_destroy
* @brief   Destroy driver state. Allows platform state to be properly released. 
* @ingroup fwd_module_management
*/
afa_result_t fwd_module_destroy(){

	unsigned int i, max_switches;
	of_switch_t** switch_list;

	//Stop the bg manager
	stop_background_tasks_manager();

	//Initialize the iomanager (Stop feeding packets)
	iomanager::destroy();

	//Stop all logical switch instances (stop processing packets)
	switch_list = physical_switch_get_logical_switches(&max_switches);
	for(i=0;i<max_switches;++i){
		if(switch_list[i] != NULL){
			fwd_module_destroy_switch_by_dpid(switch_list[i]->dpid);
		}
	}

	//Destroy interfaces
	destroy_ports();

	//Destroy physical switch (including ports)
	physical_switch_destroy();
	
	// destroy bufferpool
	bufferpool::destroy();

	//Print stats if any
	TM_DUMP_MEASUREMENTS();
	
	ROFL_INFO(FWD_MOD_NAME" forwarding module destroyed.\n");
	
	return AFA_SUCCESS; 
}

/*
* Switch management functions
*/
/**
* @brief   Checks if an LSI with the specified dpid exists 
* @ingroup logical_switch_management
*/
bool fwd_module_switch_exists(uint64_t dpid){
	return physical_switch_get_logical_switch_by_dpid(dpid) != NULL;
}

/**
* @brief   Retrieve the list of LSIs dpids
* @ingroup logical_switch_management
* @retval  List of available dpids, which MUST be deleted using dpid_list_destroy().
*/
dpid_list_t* fwd_module_get_all_lsi_dpids(void){
	return physical_switch_get_all_lsi_dpids();  
}

/**
 * @name fwd_module_get_switch_snapshot_by_dpid 
 * @brief Retrieves a snapshot of the current state of a switch port, if the port name is found. The snapshot MUST be deleted using switch_port_destroy_snapshot()
 * @ingroup logical_switch_management
 * @retval  Pointer to of_switch_snapshot_t instance or NULL 
 */
of_switch_snapshot_t* fwd_module_get_switch_snapshot_by_dpid(uint64_t dpid){
	return physical_switch_get_logical_switch_snapshot(dpid);
}


/*
* @name    fwd_module_create_switch 
* @brief   Instruct driver to create an OF logical switch 
* @ingroup logical_switch_management
* @retval  Pointer to of_switch_t instance 
*/
afa_result_t fwd_module_create_switch(char* name, uint64_t dpid, of_version_t of_version, unsigned int num_of_tables, int* ma_list){
	
	of_switch_t* sw;
	
	sw = (of_switch_t*)of1x_init_switch(name, of_version, dpid, num_of_tables, (enum of1x_matching_algorithm_available*) ma_list);

	if(unlikely(!sw))
		return AFA_FAILURE;

	//Create RX ports
	processingmanager::create_rx_pgs(sw);

	//Add switch to the bank	
	physical_switch_add_logical_switch(sw);
	
	return AFA_SUCCESS;
}

/*
* @name    fwd_module_destroy_switch_by_dpid 
* @brief   Instructs the driver to destroy the switch with the specified dpid 
* @ingroup logical_switch_management
*/
afa_result_t fwd_module_destroy_switch_by_dpid(const uint64_t dpid){

	unsigned int i;
	
	//Try to retrieve the switch
	of_switch_t* sw = physical_switch_get_logical_switch_by_dpid(dpid);
	
	if(!sw)
		return AFA_FAILURE;

	//Stop all ports and remove it from being scheduled by I/O first
	for(i=0;i<sw->max_ports;i++){

		if(sw->logical_ports[i].attachment_state == LOGICAL_PORT_STATE_ATTACHED && sw->logical_ports[i].port){
			//Take it out from the group
			if( iomanager::remove_port((ioport*)sw->logical_ports[i].port->platform_port_state) != ROFL_SUCCESS ){
				ROFL_ERR(FWD_MOD_NAME" WARNING! Error removing port %s from the iomanager for the switch: %s. This can leave the port unusable in the future.\n", sw->logical_ports[i].port->name, sw->name);
				assert(0);
			}

		}
	}
	
	//Create RX ports
	processingmanager::destroy_rx_pgs(sw);	 

	//Detach ports from switch. Do not feed more packets to the switch
	if(physical_switch_detach_all_ports_from_logical_switch(sw)!=ROFL_SUCCESS)
		return AFA_FAILURE;
	

	//Remove switch from the switch bank
	if(physical_switch_remove_logical_switch(sw)!=ROFL_SUCCESS)
		return AFA_FAILURE;
	
	return AFA_SUCCESS;
}

/*
* Port management 
*/

/**
* @brief   Checks if a port with the specified name exists 
* @ingroup port_management 
*/
bool fwd_module_port_exists(const char *name){
	return physical_switch_get_port_by_name(name) != NULL; 
}

/**
* @brief   Retrieve the list of names of the available ports of the platform. You may want to 
* 	   call fwd_module_get_port_snapshot_by_name(name) to get more information of the port 
* @ingroup port_management
* @retval  List of available port names, which MUST be deleted using switch_port_name_list_destroy().
*/
switch_port_name_list_t* fwd_module_get_all_port_names(void){
	return physical_switch_get_all_port_names(); 
}

/**
 * @name fwd_module_get_port_by_name
 * @brief Retrieves a snapshot of the current state of a switch port, if the port name is found. The snapshot MUST be deleted using switch_port_destroy_snapshot()
 * @ingroup port_management
 */
switch_port_snapshot_t* fwd_module_get_port_snapshot_by_name(const char *name){
	return physical_switch_get_port_snapshot(name); 
}

/*
* @name    fwd_module_attach_physical_port_to_switch
* @brief   Attemps to attach a system's port to switch, at of_port_num if defined, otherwise in the first empty OF port number.
* @ingroup management
*
* @param dpid Datapath ID of the switch to attach the ports to
* @param name Port name (system's name)
* @param of_port_num If *of_port_num is non-zero, try to attach to of_port_num of the logical switch, otherwise try to attach to the first available port and return the result in of_port_num
*/
afa_result_t fwd_module_attach_port_to_switch(uint64_t dpid, const char* name, unsigned int* of_port_num){

	switch_port_t* port;
	switch_port_snapshot_t* port_snapshot;
	of_switch_t* lsw;

	//Check switch existance
	lsw = physical_switch_get_logical_switch_by_dpid(dpid);
	if(!lsw){
		return AFA_FAILURE;
	}
	
	//Check if the port does exist
	port = physical_switch_get_port_by_name(name);
	if(!port)
		return AFA_FAILURE;

	//Update pipeline state
	if(*of_port_num == 0){
		//no port specified, we assign the first available
		if(physical_switch_attach_port_to_logical_switch(port,lsw,of_port_num) == ROFL_FAILURE){
			assert(0);
			return AFA_FAILURE;
		}
	}else{

		if(physical_switch_attach_port_to_logical_switch_at_port_num(port,lsw,*of_port_num) == ROFL_FAILURE){
			assert(0);
			return AFA_FAILURE;
		}
	}
	
	//Add it to the iomanager
	if(iomanager::add_port((ioport*)port->platform_port_state) != ROFL_SUCCESS){
		return AFA_FAILURE;	
	}

	//notify port attached(get first snapshot)
	port_snapshot = physical_switch_get_port_snapshot(port->name); 
	if(cmm_notify_port_add(port_snapshot)!=AFA_SUCCESS){
		//return AFA_FAILURE; //Ignore
	}
	
	return AFA_SUCCESS;
}

/**
* @name    fwd_module_connect_switches
* @brief   Attemps to connect two logical switches via a virtual port. Forwarding module may or may not support this functionality. 
* @ingroup management
*
* @param dpid_lsi1 Datapath ID of the LSI1
* @param dpid_lsi2 Datapath ID of the LSI2 
*/
afa_result_t fwd_module_connect_switches(uint64_t dpid_lsi1, switch_port_snapshot_t** port1, uint64_t dpid_lsi2, switch_port_snapshot_t** port2){

	of_switch_t *lsw1, *lsw2;
	ioport *vport1, *vport2;
	unsigned int port_num = 0; //We don't care about of the port

	//Check existance of the dpid
	lsw1 = physical_switch_get_logical_switch_by_dpid(dpid_lsi1);
	lsw2 = physical_switch_get_logical_switch_by_dpid(dpid_lsi2);

	if(!lsw1 || !lsw2){
		assert(0);
		return AFA_FAILURE;
	}
	
	//Create virtual port pair
	if(create_virtual_port_pair(lsw1, &vport1, lsw2, &vport2) != ROFL_SUCCESS){
		assert(0);
		return AFA_FAILURE;
	}

	//Attach both ports
	if(fwd_module_attach_port_to_switch(dpid_lsi1, vport1->of_port_state->name, &port_num) != AFA_SUCCESS){
		assert(0);
		return AFA_FAILURE;
	}
	port_num=0;
	if(fwd_module_attach_port_to_switch(dpid_lsi2, vport2->of_port_state->name, &port_num) != AFA_SUCCESS){
		assert(0);
		return AFA_FAILURE;
	}

	//Enable interfaces (start packet transmission)
	if(fwd_module_bring_port_up(vport1->of_port_state->name) != AFA_SUCCESS || fwd_module_bring_port_up(vport2->of_port_state->name) != AFA_SUCCESS){
		ROFL_ERR(FWD_MOD_NAME" ERROR: unable to bring up vlink ports.\n");
		assert(0);
		return AFA_FAILURE;
	}
	

	//Set switch ports and return
	*port1 = physical_switch_get_port_snapshot(vport1->of_port_state->name);
	*port2 = physical_switch_get_port_snapshot(vport2->of_port_state->name);

	return AFA_SUCCESS; 
}

/*
* @name    fwd_module_detach_port_from_switch
* @brief   Detaches a port from the switch 
* @ingroup port_management
*
* @param dpid Datapath ID of the switch to detach the ports
* @param name Port name (system's name)
*/
afa_result_t fwd_module_detach_port_from_switch(uint64_t dpid, const char* name){

	of_switch_t* lsw;
	switch_port_t* port;
	switch_port_snapshot_t* port_snapshot;
	
	lsw = physical_switch_get_logical_switch_by_dpid(dpid);
	if(!lsw)
		return AFA_FAILURE;

	port = physical_switch_get_port_by_name(name);

	//Check if the port does exist and is really attached to the dpid
	if( !port || port->attached_sw->dpid != dpid)
		return AFA_FAILURE;

	if(physical_switch_detach_port_from_logical_switch(port,lsw) != ROFL_SUCCESS)
		return AFA_FAILURE;
	
	//Remove counter port from the iomanager
	if(port->type == PORT_TYPE_VIRTUAL){
		switch_port_t* port_pair = get_vlink_pair(port); 
		switch_port_snapshot_t* port_pair_snapshot;

		if(!port_pair){
			ROFL_ERR(FWD_MOD_NAME" Error detaching a virtual link port. Could not find the counter port of %s.\n",port->name);
			assert(0);
			return AFA_FAILURE;
		}
	
		if(!port_pair->attached_sw || physical_switch_detach_port_from_logical_switch(port_pair,port_pair->attached_sw) != ROFL_SUCCESS){
			ROFL_ERR(FWD_MOD_NAME" Error detaching port-pair %s from the sw.\n",port_pair->name);
			assert(0);
			return AFA_FAILURE;
		}

		//Remove it from the iomanager
		if(iomanager::remove_port((ioport*)port_pair->platform_port_state) != ROFL_SUCCESS){
			ROFL_ERR(FWD_MOD_NAME" Error removing port %s from the iomanager. The port may become unusable...\n",port->name);
			assert(0);
			return AFA_FAILURE;
		}

		//notify port dettached
		port_pair_snapshot = physical_switch_get_port_snapshot(port_pair->name);
		if(cmm_notify_port_delete(port_pair_snapshot) != AFA_SUCCESS){
			///return AFA_FAILURE; //ignore
		}	
		
		//Remove from the pipeline and delete
		if(physical_switch_remove_port(port_pair->name) != ROFL_SUCCESS){
			ROFL_ERR(FWD_MOD_NAME" Error removing port from the physical_switch. The port may become unusable...\n");
			assert(0);
			return AFA_FAILURE;
			
		}
		delete (ioport*)port_pair->platform_port_state;
	}
	
	//Remove it from the iomanager(
	if(iomanager::remove_port((ioport*)port->platform_port_state) != ROFL_SUCCESS){
		ROFL_ERR(FWD_MOD_NAME" Error removing port %s from the iomanager. The port may become unusable...\n",port->name);
		assert(0);
	}

	//notify port dettached
	port_snapshot = physical_switch_get_port_snapshot(port->name); 
	if(cmm_notify_port_delete(port_snapshot) != AFA_SUCCESS){
		///return AFA_FAILURE; //ignore
	}

	//If it is virtual remove also the data structures associated
	if(port->type == PORT_TYPE_VIRTUAL){
		//Remove from the pipeline and delete
		if(physical_switch_remove_port(port->name) != ROFL_SUCCESS){
			ROFL_ERR(FWD_MOD_NAME" Error removing port from the physical_switch. The port may become unusable...\n");
			assert(0);
			return AFA_FAILURE;
			
		}
		delete (ioport*)port->platform_port_state;
		
	}
	
	return AFA_SUCCESS; 
}


/*
* @name    fwd_module_detach_port_from_switch_at_port_num
* @brief   Detaches port_num of the logical switch identified with dpid 
* @ingroup port_management
*
* @param dpid Datapath ID of the switch to detach the ports
* @param of_port_num Number of the port (OF number) 
*/
afa_result_t fwd_module_detach_port_from_switch_at_port_num(uint64_t dpid, const unsigned int of_port_num){

	of_switch_t* lsw;
	
	lsw = physical_switch_get_logical_switch_by_dpid(dpid);
	if(!lsw)
		return AFA_FAILURE;

	//Check if the port does exist.
	if(!of_port_num || of_port_num >= LOGICAL_SWITCH_MAX_LOG_PORTS || !lsw->logical_ports[of_port_num].port)
		return AFA_FAILURE;

	return fwd_module_detach_port_from_switch(dpid, lsw->logical_ports[of_port_num].port->name);
}


//Port admin up/down stuff

/*
* Port administrative management actions (ifconfig up/down like)
*/

/*
* @name    fwd_module_bring_port_up
* @brief   Brings up a system port. If the port is attached to an OF logical switch, this also schedules port for I/O and triggers PORTMOD message. 
* @ingroup port_management
*
* @param name Port system name 
*/
afa_result_t fwd_module_bring_port_up(const char* name){

	switch_port_t* port;
	switch_port_snapshot_t* port_snapshot;

	//Check if the port does exist
	port = physical_switch_get_port_by_name(name);

	if(!port || !port->platform_port_state)
		return AFA_FAILURE;

	//Bring it up
	if(port->attached_sw){
		//Port is attached and belonging to a port group. Instruct I/O manager to start the port
		if(iomanager::bring_port_up((ioport*)port->platform_port_state)!=ROFL_SUCCESS)
			return AFA_FAILURE;
	}else{
		//The port is not attached. Only bring it up (ifconfig up)
		if(enable_port(port->platform_port_state)!=ROFL_SUCCESS)
			return AFA_FAILURE;
	}

	port_snapshot = physical_switch_get_port_snapshot(port->name); 
	if(cmm_notify_port_status_changed(port_snapshot)!=AFA_SUCCESS)
		return AFA_FAILURE;
	
	return AFA_SUCCESS;
}

/*
* @name    fwd_module_bring_port_down
* @brief   Shutdowns (brings down) a system port. If the port is attached to an OF logical switch, this also de-schedules port and triggers PORTMOD message. 
* @ingroup port_management
*
* @param name Port system name 
*/
afa_result_t fwd_module_bring_port_down(const char* name){

	switch_port_t* port;
	switch_port_snapshot_t* port_snapshot;
	
	//Check if the port does exist
	port = physical_switch_get_port_by_name(name);
	if(!port || !port->platform_port_state)
		return AFA_FAILURE;

	//Bring it down
	if(port->attached_sw){
		//Port is attached and belonging to a port group. Instruct I/O manager to stop the port
		if( iomanager::bring_port_down((ioport*)port->platform_port_state)!=ROFL_SUCCESS)
			return AFA_FAILURE;
	}else{
		//The port is not attached. Only bring it down (ifconfig down)
		if(disable_port(port->platform_port_state)==ROFL_FAILURE)
			return AFA_FAILURE;
	}

	port_snapshot = physical_switch_get_port_snapshot(port->name); 
	if(cmm_notify_port_status_changed(port_snapshot)!=AFA_SUCCESS)
		return AFA_FAILURE;
	
	return AFA_SUCCESS;
}

/*
* @name    fwd_module_bring_port_up_by_num
* @brief   Brings up a port from an OF logical switch (and the underlying physical interface). This function also triggers the PORTMOD message 
* @ingroup port_management
*
* @param dpid DatapathID 
* @param port_num OF port number
*/
afa_result_t fwd_module_bring_port_up_by_num(uint64_t dpid, unsigned int port_num){

	of_switch_t* lsw;
	switch_port_snapshot_t* port_snapshot;
	
	lsw = physical_switch_get_logical_switch_by_dpid(dpid);
	if(!lsw)
		return AFA_FAILURE;

	//Check if the port does exist and is really attached to the dpid
	if( !lsw->logical_ports[port_num].port || lsw->logical_ports[port_num].attachment_state != LOGICAL_PORT_STATE_ATTACHED || lsw->logical_ports[port_num].port->attached_sw->dpid != dpid)
		return AFA_FAILURE;

	//Call I/O manager to bring it up
	if(iomanager::bring_port_up((ioport*)lsw->logical_ports[port_num].port->platform_port_state) != ROFL_SUCCESS)
		return AFA_FAILURE;
	
	port_snapshot = physical_switch_get_port_snapshot(lsw->logical_ports[port_num].port->name); 
	if(cmm_notify_port_status_changed(port_snapshot)!=AFA_SUCCESS)
		return AFA_FAILURE;
	
	return AFA_SUCCESS;
}

/*
* @name    fwd_module_bring_port_down_by_num
* @brief   Brings down a port from an OF logical switch (and the underlying physical interface). This also triggers the PORTMOD message.
* @ingroup port_management
*
* @param dpid DatapathID 
* @param port_num OF port number
*/
afa_result_t fwd_module_bring_port_down_by_num(uint64_t dpid, unsigned int port_num){

	of_switch_t* lsw;
	switch_port_snapshot_t* port_snapshot;
	
	lsw = physical_switch_get_logical_switch_by_dpid(dpid);
	if(!lsw)
		return AFA_FAILURE;

	//Check if the port does exist and is really attached to the dpid
	if( !lsw->logical_ports[port_num].port || lsw->logical_ports[port_num].attachment_state != LOGICAL_PORT_STATE_ATTACHED || lsw->logical_ports[port_num].port->attached_sw->dpid != dpid)
		return AFA_FAILURE;

	//Call I/O manager to bring it down
	if(iomanager::bring_port_down((ioport*)lsw->logical_ports[port_num].port->platform_port_state) != ROFL_SUCCESS)
		return AFA_FAILURE;
	
	port_snapshot = physical_switch_get_port_snapshot(lsw->logical_ports[port_num].port->name); 
	if(cmm_notify_port_status_changed(port_snapshot)!=AFA_SUCCESS)
		return AFA_FAILURE;
	
	return AFA_SUCCESS;
}

/**
 * @brief Retrieve a snapshot of the monitoring state. If rev is 0, or the current monitoring 
 * has changed (monitoring->rev != rev), a new snapshot of the monitoring state is made. Warning: this 
 * is expensive.
 * @ingroup fwd_module_management
 *
 * @param rev Last seen revision. Set to 0 to always get a new snapshot 
 * @return A snapshot of the monitoring state that MUST be destroyed using monitoring_destroy_snapshot() or NULL if there have been no changes (same rev)
 */ 
monitoring_snapshot_state_t* fwd_module_get_monitoring_snapshot(uint64_t rev){

	monitoring_state_t* mon = physical_switch_get_monitoring();

	if( rev == 0 || monitoring_has_changed(mon, &rev) ) 
		return monitoring_get_snapshot(mon);

	return NULL;
}

/**
 * @brief get a list of available matching algorithms
 * @ingroup fwd_module_management
 *
 * @param of_version
 * @param name_list
 * @param count
 * @return
 */
afa_result_t fwd_module_list_matching_algorithms(of_version_t of_version, const char * const** name_list, int *count){
	return (afa_result_t)of_get_switch_matching_algorithms(of_version, name_list, count);
}
