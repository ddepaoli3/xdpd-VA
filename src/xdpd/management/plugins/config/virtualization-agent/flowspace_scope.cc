/*
 * flowspace_scope.cc
 *
 *  @author Daniel Depaoli <daniel.depaoli (at) create-net.org>
 */

#include "flowspace_scope.h"
#include "../../../../virtualization-agent/virtualagent.h"

using namespace xdpd;
using namespace rofl;

#define FLOWSPACE_ID "id"
#define FLOWSPACE_PRIORITY "priority"
#define FLOWSPACE_VLAN "vlan"
#define FLOWSPACE_DPNAME "flowspace_dpname"
#define FLOWSPACE_SLICE_ACTION "slice_action"
#define max_priority 1000

/**
 * Flowspace match
 * Most of them to be implemented
 */
#define FLOWSPACE_RULE_IN_PORT	"in_port"
#define FLOWSPACE_RULE_IN_PHY_PORT	"in_phy_port"
#define FLOWSPACE_RULE_METADATA	"metadata"
#define FLOWSPACE_RULE_ETH_DST	"eth_dst"
#define FLOWSPACE_RULE_ETH_SRC	"eth_src"
#define FLOWSPACE_RULE_ETH_TYPE	"eth_type"
#define FLOWSPACE_RULE_VLAN_VID	"vlan_vid"
#define FLOWSPACE_RULE_VLAN_PCP	"vlan_pcp"
#define FLOWSPACE_RULE_MPLS_LABEL	"mpls_label"
#define FLOWSPACE_RULE_MPLS_TC	"mpls_tc"
#define FLOWSPACE_RULE_MPLS_BOS	"mpls_bos"
#define FLOWSPACE_RULE_ARP_OP	"arp_op"
#define FLOWSPACE_RULE_ARP_SPA	"arp_spa"
#define FLOWSPACE_RULE_ARP_TPA	"arp_tpa"
#define FLOWSPACE_RULE_ARP_SHA	"arp_sha"
#define FLOWSPACE_RULE_ARP_THA	"arp_tha"
#define FLOWSPACE_RULE_NW_PROTO	"nw_proto"
#define FLOWSPACE_RULE_NW_SRC	"nw_src"
#define FLOWSPACE_RULE_NW_DST	"nw_dst"
#define FLOWSPACE_RULE_IP_DSCP	"ip_dscp"
#define FLOWSPACE_RULE_IP_ECN	"ip_ecn"
#define FLOWSPACE_RULE_IP_PROTO	"ip_proto"
#define FLOWSPACE_RULE_IPV4_SRC	"ipv4_src"
#define FLOWSPACE_RULE_IPV4_DST	"ipv4_dst"
#define FLOWSPACE_RULE_IPV6_SRC	"ipv6_src"
#define FLOWSPACE_RULE_IPV6_DST	"ipv6_dst"
#define FLOWSPACE_RULE_IPV6_FLABEL	"ipv6_flabel"
#define FLOWSPACE_RULE_ICMPV6_TYPE	"icmpv6_type"
#define FLOWSPACE_RULE_ICMPV6_CODE	"icmpv6_code"
#define FLOWSPACE_RULE_IPV6_ND_TARGET	"ipv6_nd_target"
#define FLOWSPACE_RULE_IPV6_ND_SLL	"ipv6_nd_sll"
#define FLOWSPACE_RULE_IPV6_ND_TLL	"ipv6_nd_tll"
#define FLOWSPACE_RULE_IPV6_EXTHDR	"ipv6_exthdr"
#define FLOWSPACE_RULE_TP_SRC	"tp_src"
#define FLOWSPACE_RULE_TP_DST	"tp_dst"
#define FLOWSPACE_RULE_TCP_SRC	"tcp_src"
#define FLOWSPACE_RULE_TCP_DST	"tcp_dst"
#define FLOWSPACE_RULE_UDP_SRC	"udp_src"
#define FLOWSPACE_RULE_UDP_DST	"udp_dst"
#define FLOWSPACE_RULE_SCTP_SRC	"sctp_src"
#define FLOWSPACE_RULE_SCTP_DST	"sctp_dst"
#define FLOWSPACE_RULE_ICMPV4_TYPE	"icmpv4_type"
#define FLOWSPACE_RULE_ICMPV4_CODE	"icmpv4_code"
#define FLOWSPACE_RULE_PBB_ISID	"pbb_isid"
#define FLOWSPACE_RULE_TUNNEL_ID	"tunnel_id"
#define FLOWSPACE_RULE_PPPOE_CODE	"pppoe_code"
#define FLOWSPACE_RULE_PPPOE_TYPE	"pppoe_type"
#define FLOWSPACE_RULE_PPPOE_SID	"pppoe_sid"
#define FLOWSPACE_RULE_PPP_PROT	"ppp_prot"
#define FLOWSPACE_RULE_GTP_MSG_TYPE	"gtp_msg_type"
#define FLOWSPACE_RULE_GTP_TEID	"gtp_teid"
#define FLOWSPACE_RULE_MAX	"max"



flowspace_scope::flowspace_scope(std::string name, bool mandatory):scope(name, mandatory){
	register_parameter(FLOWSPACE_ID, false);
	register_parameter(FLOWSPACE_PRIORITY, true);
	register_parameter(FLOWSPACE_VLAN, false);
	register_parameter(FLOWSPACE_DPNAME, true);
	register_parameter(FLOWSPACE_SLICE_ACTION, true);

	// Parameter defining flowspace
	register_parameter(FLOWSPACE_RULE_IN_PORT, false);
	register_parameter(FLOWSPACE_RULE_IN_PHY_PORT, false);
	register_parameter(FLOWSPACE_RULE_METADATA, false);
	register_parameter(FLOWSPACE_RULE_ETH_DST, false);
	register_parameter(FLOWSPACE_RULE_ETH_SRC, false);
	register_parameter(FLOWSPACE_RULE_ETH_TYPE, false);
	register_parameter(FLOWSPACE_RULE_VLAN_VID, false);
	register_parameter(FLOWSPACE_RULE_VLAN_PCP, false);
	register_parameter(FLOWSPACE_RULE_MPLS_LABEL, false);
	register_parameter(FLOWSPACE_RULE_MPLS_TC, false);
	register_parameter(FLOWSPACE_RULE_MPLS_BOS, false);
	register_parameter(FLOWSPACE_RULE_ARP_OP, false);
	register_parameter(FLOWSPACE_RULE_ARP_SPA, false);
	register_parameter(FLOWSPACE_RULE_ARP_TPA, false);
	register_parameter(FLOWSPACE_RULE_ARP_SHA, false);
	register_parameter(FLOWSPACE_RULE_ARP_THA, false);
	register_parameter(FLOWSPACE_RULE_NW_PROTO, false);
	register_parameter(FLOWSPACE_RULE_NW_SRC, false);
	register_parameter(FLOWSPACE_RULE_NW_DST, false);
	register_parameter(FLOWSPACE_RULE_IP_DSCP, false);
	register_parameter(FLOWSPACE_RULE_IP_ECN, false);
	register_parameter(FLOWSPACE_RULE_IP_PROTO, false);
	register_parameter(FLOWSPACE_RULE_IPV4_SRC, false);
	register_parameter(FLOWSPACE_RULE_IPV4_DST, false);
	register_parameter(FLOWSPACE_RULE_IPV6_SRC, false);
	register_parameter(FLOWSPACE_RULE_IPV6_DST, false);
	register_parameter(FLOWSPACE_RULE_IPV6_FLABEL, false);
	register_parameter(FLOWSPACE_RULE_ICMPV6_TYPE, false);
	register_parameter(FLOWSPACE_RULE_ICMPV6_CODE, false);
	register_parameter(FLOWSPACE_RULE_IPV6_ND_TARGET, false);
	register_parameter(FLOWSPACE_RULE_IPV6_ND_SLL, false);
	register_parameter(FLOWSPACE_RULE_IPV6_ND_TLL, false);
	register_parameter(FLOWSPACE_RULE_IPV6_EXTHDR, false);
	register_parameter(FLOWSPACE_RULE_TP_SRC, false);
	register_parameter(FLOWSPACE_RULE_TP_DST, false);
	register_parameter(FLOWSPACE_RULE_TCP_SRC, false);
	register_parameter(FLOWSPACE_RULE_TCP_DST, false);
	register_parameter(FLOWSPACE_RULE_UDP_SRC, false);
	register_parameter(FLOWSPACE_RULE_UDP_DST, false);
	register_parameter(FLOWSPACE_RULE_SCTP_SRC, false);
	register_parameter(FLOWSPACE_RULE_SCTP_DST, false);
	register_parameter(FLOWSPACE_RULE_ICMPV4_TYPE, false);
	register_parameter(FLOWSPACE_RULE_ICMPV4_CODE, false);
	register_parameter(FLOWSPACE_RULE_PBB_ISID, false);
	register_parameter(FLOWSPACE_RULE_TUNNEL_ID, false);
	register_parameter(FLOWSPACE_RULE_PPPOE_CODE, false);
	register_parameter(FLOWSPACE_RULE_PPPOE_TYPE, false);
	register_parameter(FLOWSPACE_RULE_PPPOE_SID, false);
	register_parameter(FLOWSPACE_RULE_PPP_PROT, false);
	register_parameter(FLOWSPACE_RULE_GTP_MSG_TYPE, false);
	register_parameter(FLOWSPACE_RULE_GTP_TEID, false);
	register_parameter(FLOWSPACE_RULE_MAX, false);
}

flowspace_scope::~flowspace_scope() {
	// TODO Auto-generated destructor stub
}

 bool order_by_priority(flowspace_struct_t* first, flowspace_struct_t* second) {
	return first->priority > second->priority;
}


void xdpd::flowspace_scope::post_validate(libconfig::Setting& setting,
		bool dry_run) {

if (virtual_agent::is_active() ) //Otherwise skip all this function
{
	int priority = 1;
	std::string	slice_action;
	std::string	flowspace_dpname;
	std::string flowspace_name;

	if (setting.exists(FLOWSPACE_PRIORITY) && setting.exists(FLOWSPACE_DPNAME))
	{

		// Check slice_action
		std::string _slice_action = setting[FLOWSPACE_SLICE_ACTION];
		slice_action = _slice_action;

		// Check list of datapaths
		if (!setting[FLOWSPACE_DPNAME].isList())
		{
			ROFL_ERR("[Virtual Agent] %s must be a list of datapaths. Error at line %i\n", FLOWSPACE_DPNAME, setting[FLOWSPACE_DPNAME].getSourceLine());
			throw eConfParseError();
		}

		for(int i=0; i<setting[FLOWSPACE_DPNAME].getLength(); ++i)
		{
			// Check datapath existance
			std::string _flowspace_dpname = setting[FLOWSPACE_DPNAME][i];
			flowspace_dpname = _flowspace_dpname;

			if (!switch_manager::exists_by_name(flowspace_dpname)  && !dry_run)
			{
				ROFL_ERR("[Virtual Agent] %s doesn't exist! Impossible to add the flowspace. Error at line %i\n", flowspace_dpname.c_str(), setting[FLOWSPACE_DPNAME].getSourceLine());
				throw eConfParseError();
			}

			// Check priority
			priority = setting[FLOWSPACE_PRIORITY];
			if (priority < 1 || priority > max_priority)
			{
				ROFL_ERR("[Virtual Agent] %s: Invalid priority. Must be [1-%i]", setting.getPath().c_str(), max_priority);
			}

			if(!dry_run){

				if ( virtual_agent::check_slice_existance(_slice_action,flowspace_dpname))
				{
					//slice* slice_to_add;
					flowspace_name = setting.getName();

					flowspace_struct_t* flowspaceStruct = new flowspace_struct_t;
					//Define priority and slice
					flowspaceStruct->slice = _slice_action;
					flowspaceStruct->priority = priority;
					flowspaceStruct->name = flowspace_name;

					// Load parameters that define flowspace];
					flowspace_scope::validate_flowspace_registration(setting,dry_run,flowspaceStruct);

					virtual_agent::list_switch_by_name[_flowspace_dpname]->flowspace_struct_list.push_front(flowspaceStruct);
					//virtual_agent::list_switch_by_name[_flowspace_dpname]->flowspace_struct_list.sort(order_by_priority);

					/////
					//Just for debug
					/////
					if (false)
					{
						va_switch* vaswitch = virtual_agent::list_switch_by_name[_flowspace_dpname];
						std::list<flowspace_struct_t*>::iterator _flowspace; //single flowspace
						std::list<flowspace_match_t*>::iterator _match;		// single match
						flowspace_struct_t* tempFlowspace;
					//	flowspace_match_t* tempMatch;
						//slice* slice = NULL;

						//bool matched = false;

						for (_flowspace = vaswitch->flowspace_struct_list.begin();
								_flowspace != vaswitch->flowspace_struct_list.end();
								_flowspace++)
						{
							tempFlowspace = *_flowspace;
							ROFL_INFO("Inside %s\n", tempFlowspace->name.c_str());
							std::list<flowspace_match_t*> it = tempFlowspace->match_list;
							flowspace_match_t* tempMatch;
							for (_match = it.begin();
										_match != it.end();
										_match ++)
								{
									tempMatch = *_match;
									ROFL_INFO("Value=%i, Type=%i \n", tempMatch->value->value.u16, tempMatch->type);

								}
						}
					}
					/////
					//end debug
					/////

				}
				else
				{
					ROFL_INFO("[Virtual Agent] Slice %s doesn't exist for switch %s. Line %i\n",
							_slice_action.c_str(),_flowspace_dpname.c_str(), setting[FLOWSPACE_SLICE_ACTION].getSourceLine());
					throw eConfParseError();
				}

				}
		}




	}

} // end if virtual_agent::is_active
}

void xdpd::flowspace_scope::validate_flowspace_registration(
		libconfig::Setting& setting, bool dry_run, flowspace_struct_t* flowspaceStruct) {

	bool vlan_present = false; // Ensure vlan is present

	if (setting.exists(FLOWSPACE_RULE_IN_PORT ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_IN_PORT );
	if (setting.exists(FLOWSPACE_RULE_IN_PHY_PORT ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_IN_PHY_PORT );
	if (setting.exists(FLOWSPACE_RULE_METADATA ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_METADATA );
	if (setting.exists(FLOWSPACE_RULE_ETH_DST ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_ETH_DST );
	if (setting.exists(FLOWSPACE_RULE_ETH_SRC ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_ETH_SRC );
	if (setting.exists(FLOWSPACE_RULE_ETH_TYPE ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_ETH_TYPE );
	if (setting.exists(FLOWSPACE_RULE_VLAN_VID ))
	{
		flowspace_match_t* match_vlanvid = new flowspace_match_t;
		utern_t* uternvalue_vlanvid = new utern_t;
		//Create the match
		match_vlanvid->type = FLOWSPACE_MATCH_VLAN_VID;
		int vlan = setting[FLOWSPACE_RULE_VLAN_VID];
		uternvalue_vlanvid->value.u16 = vlan;
		uternvalue_vlanvid->type = UTERN16_T;
		uternvalue_vlanvid->mask.u16 = ~0;
		match_vlanvid->value = uternvalue_vlanvid;

		//Update the match in the list
		flowspaceStruct->match_list.push_front(match_vlanvid);
		ROFL_INFO("[%s]Inserisco vlan=%i\n", __FILE__,match_vlanvid->value->value.u16);
		vlan_present = true;
	}
	if (setting.exists(FLOWSPACE_RULE_VLAN_PCP ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_VLAN_PCP );
	if (setting.exists(FLOWSPACE_RULE_MPLS_LABEL ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_MPLS_LABEL );
	if (setting.exists(FLOWSPACE_RULE_MPLS_TC ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_MPLS_TC );
	if (setting.exists(FLOWSPACE_RULE_MPLS_BOS ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_MPLS_BOS );
	if (setting.exists(FLOWSPACE_RULE_ARP_OP ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_ARP_OP );
	if (setting.exists(FLOWSPACE_RULE_ARP_SPA ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_ARP_SPA );
	if (setting.exists(FLOWSPACE_RULE_ARP_TPA ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_ARP_TPA );
	if (setting.exists(FLOWSPACE_RULE_ARP_SHA ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_ARP_SHA );
	if (setting.exists(FLOWSPACE_RULE_ARP_THA ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_ARP_THA );
	if (setting.exists(FLOWSPACE_RULE_NW_PROTO ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_NW_PROTO );
	if (setting.exists(FLOWSPACE_RULE_NW_SRC ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_NW_SRC );
	if (setting.exists(FLOWSPACE_RULE_NW_DST ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_NW_DST );
	if (setting.exists(FLOWSPACE_RULE_IP_DSCP ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_IP_DSCP );
	if (setting.exists(FLOWSPACE_RULE_IP_ECN ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_IP_ECN );
	if (setting.exists(FLOWSPACE_RULE_IP_PROTO ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_IP_PROTO );
	if (setting.exists(FLOWSPACE_RULE_IPV4_SRC ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_IPV4_SRC );
	if (setting.exists(FLOWSPACE_RULE_IPV4_DST ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_IPV4_DST );
	if (setting.exists(FLOWSPACE_RULE_IPV6_SRC ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_IPV6_SRC );
	if (setting.exists(FLOWSPACE_RULE_IPV6_DST ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_IPV6_DST );
	if (setting.exists(FLOWSPACE_RULE_IPV6_FLABEL ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_IPV6_FLABEL );
	if (setting.exists(FLOWSPACE_RULE_ICMPV6_TYPE ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_ICMPV6_TYPE );
	if (setting.exists(FLOWSPACE_RULE_ICMPV6_CODE ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_ICMPV6_CODE );
	if (setting.exists(FLOWSPACE_RULE_IPV6_ND_TARGET ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_IPV6_ND_TARGET );
	if (setting.exists(FLOWSPACE_RULE_IPV6_ND_SLL ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_IPV6_ND_SLL );
	if (setting.exists(FLOWSPACE_RULE_IPV6_ND_TLL ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_IPV6_ND_TLL );
	if (setting.exists(FLOWSPACE_RULE_IPV6_EXTHDR ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_IPV6_EXTHDR );
	if (setting.exists(FLOWSPACE_RULE_TP_SRC ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_TP_SRC );
	if (setting.exists(FLOWSPACE_RULE_TP_DST ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_TP_DST );
	if (setting.exists(FLOWSPACE_RULE_TCP_SRC ))
	{
		flowspace_match_t* match_tcpsrc = new flowspace_match_t;
		utern_t* uternvalue_tcpsrc = new utern_t;
		//Create the match
		match_tcpsrc->type = FLOWSPACE_MATCH_TCP_SRC;
		int tp_src = setting[FLOWSPACE_RULE_TCP_SRC];
		uternvalue_tcpsrc->value.u16 = tp_src;
		uternvalue_tcpsrc->type = UTERN16_T;
		uternvalue_tcpsrc->mask.u16 = ~0;
		match_tcpsrc->value = uternvalue_tcpsrc;

		//Update the match in the list
		flowspaceStruct->match_list.push_front(match_tcpsrc);

		//ROFL_INFO("Loading %s. value=%i\n",FLOWSPACE_RULE_TCP_SRC, match_tcpsrc->value->value.u16 );

		///////////////////////
		///////////////////////
		//Create the match
		flowspace_match_t* match_tcpsrc2 = new flowspace_match_t;
		utern_t* uternvalue_tcpsrc2 = new utern_t;
		match_tcpsrc2->type = FLOWSPACE_MATCH_TP_SRC;
		tp_src = setting[FLOWSPACE_RULE_TCP_SRC];
		uternvalue_tcpsrc2->value.u16 = tp_src;
		uternvalue_tcpsrc2->type = UTERN16_T;
		uternvalue_tcpsrc2->mask.u16 = ~0;
		match_tcpsrc2->value = uternvalue_tcpsrc2;

		//Update the match in the list
		flowspaceStruct->match_list.push_front(match_tcpsrc2);
	}
	if (setting.exists(FLOWSPACE_RULE_TCP_DST ))
	{
		flowspace_match_t* match_tcpdst = new flowspace_match_t;
		utern_t* uternvalue_tcpdst = new utern_t;
		//Create the match
		match_tcpdst->type = FLOWSPACE_MATCH_TCP_DST;
		int tp_src = setting[FLOWSPACE_RULE_TCP_DST];
		uternvalue_tcpdst->value.u16 = tp_src;
		uternvalue_tcpdst->type = UTERN16_T;
		uternvalue_tcpdst->mask.u16 = ~0;
		match_tcpdst->value = uternvalue_tcpdst;

		//Update the match in the list
		flowspaceStruct->match_list.push_front(match_tcpdst);

		///////////////////
		//////////////////
		//Create the match
		flowspace_match_t* match_tcpdst2 = new flowspace_match_t;
		utern_t* uternvalue_tcpdst2 = new utern_t;
		match_tcpdst2->type = FLOWSPACE_MATCH_TP_DST;
		tp_src = setting[FLOWSPACE_RULE_TCP_DST];
		uternvalue_tcpdst2->value.u16 = tp_src;
		uternvalue_tcpdst2->type = UTERN16_T;
		uternvalue_tcpdst2->mask.u16 = ~0;
		match_tcpdst2->value = uternvalue_tcpdst2;

		//Update the match in the list
		flowspaceStruct->match_list.push_front(match_tcpdst2);

		//ROFL_INFO("Loading %s. value=%i\n",FLOWSPACE_RULE_TCP_SRC, match_tcpdst->value->value.u16 );
	}
	if (setting.exists(FLOWSPACE_RULE_UDP_SRC ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_UDP_SRC );
	if (setting.exists(FLOWSPACE_RULE_UDP_DST ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_UDP_DST );
	if (setting.exists(FLOWSPACE_RULE_SCTP_SRC ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_SCTP_SRC );
	if (setting.exists(FLOWSPACE_RULE_SCTP_DST ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_SCTP_DST );
	if (setting.exists(FLOWSPACE_RULE_ICMPV4_TYPE ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_ICMPV4_TYPE );
	if (setting.exists(FLOWSPACE_RULE_ICMPV4_CODE ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_ICMPV4_CODE );
	if (setting.exists(FLOWSPACE_RULE_PBB_ISID ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_PBB_ISID );
	if (setting.exists(FLOWSPACE_RULE_TUNNEL_ID ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_TUNNEL_ID );
	if (setting.exists(FLOWSPACE_RULE_PPPOE_CODE ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_PPPOE_CODE );
	if (setting.exists(FLOWSPACE_RULE_PPPOE_TYPE ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_PPPOE_TYPE );
	if (setting.exists(FLOWSPACE_RULE_PPPOE_SID ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_PPPOE_SID );
	if (setting.exists(FLOWSPACE_RULE_PPP_PROT ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_PPP_PROT );
	if (setting.exists(FLOWSPACE_RULE_GTP_MSG_TYPE ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_GTP_MSG_TYPE );
	if (setting.exists(FLOWSPACE_RULE_GTP_TEID ))
		ROFL_INFO("%s not yet avaible\n",FLOWSPACE_RULE_GTP_TEID );

	if (!vlan_present)
	{
		ROFL_INFO("Flowspace %s without vlan_vid parameter. Up to now it is necessary\n", flowspaceStruct->name.c_str());
		throw eConfParseError();
	}

}
