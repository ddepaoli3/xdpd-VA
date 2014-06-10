/*
 * va_switch.cc
 *
 *  @author Daniel Depaoli <daniel.depaoli (at) create-net.org>
 */

#include "va_switch.h"
#include "virtualagent.h"
#include "flowspace.h"
#include <bitset>
#include "rofl/datapath/pipeline/common/protocol_constants.h"


va_switch::va_switch() {
	// TODO Auto-generated constructor stub
}

va_switch::va_switch(std::string dp_name ,uint64_t dp_id)
{
	this->dp_id = dp_id;
	this->dp_name = dp_name;
}



va_switch::~va_switch() {
	// TODO Auto-generated destructor stub
}


slice* va_switch::select_slice(crofctl* controller) {

	std::map<std::string, crofctl*>::iterator iter;

	//iterate through controller map
	for (iter = this->controller_map.begin();
			iter != this->controller_map.end();
			iter ++)
	{
		if (iter->second == controller)
			return this->get_slice(iter->first);
	}

	return NULL;

}

slice* va_switch::get_slice(std::string name) {

	slice* _slice;
	for (std::list<slice*>::iterator it = this->slice_list.begin();
			it != this->slice_list.end();
			it++)
	{
		_slice = *it;
		if (strcmp(_slice->name.c_str(), name.c_str()) == 0)
			return _slice;
	}

	return NULL;

}


bool va_switch::check_match(const packet_matches_t pkt, std::list<flowspace_match_t*> it) {

	std::list<flowspace_match_t*>::iterator _match;		// single match
	flowspace_match_t* tempMatch;

	for (_match = it.begin();
			_match != it.end();
			_match ++)
	{
		tempMatch = *_match;
		if (!va_switch::compare_match_flow(&pkt, tempMatch) )
		{
			return false;
		}

	}
		return true;
}


bool va_switch::compare_match_flow(const packet_matches_t* pkt,
		flowspace_match_t* it) {
	if(!it)
		return false;
	switch(it->type){
		//Phy
		case FLOWSPACE_MATCH_IN_PORT: return __utern_compare32(it->value, &pkt->__port_in);
		case FLOWSPACE_MATCH_IN_PHY_PORT: if(!pkt->__port_in) return false; //According to spec
					return __utern_compare32(it->value, &pkt->__phy_port_in);
		//Metadata
	  	case FLOWSPACE_MATCH_METADATA: return __utern_compare64(it->value, &pkt->__metadata);

		//802
   		case FLOWSPACE_MATCH_ETH_DST:  return __utern_compare64(it->value, &pkt->__eth_dst);
   		case FLOWSPACE_MATCH_ETH_SRC:  return __utern_compare64(it->value, &pkt->__eth_src);
   		case FLOWSPACE_MATCH_ETH_TYPE: return __utern_compare16(it->value, &pkt->__eth_type);

		//802.1q
   		case FLOWSPACE_MATCH_VLAN_VID:
   			{
   				//return __utern_compare16(it->value, (&pkt->__vlan_vid)>>8);
   				return ((it->value->value.u16) == (pkt->__vlan_vid)>>8);
   			}
   		case FLOWSPACE_MATCH_VLAN_PCP: return pkt->__has_vlan &&  __utern_compare8(it->value, &pkt->__vlan_pcp);

		//MPLS
   		case FLOWSPACE_MATCH_MPLS_LABEL: if(!(pkt->__eth_type == ETH_TYPE_MPLS_UNICAST || pkt->__eth_type == ETH_TYPE_MPLS_MULTICAST )) return false;
					return __utern_compare32(it->value, &pkt->__mpls_label);
   		case FLOWSPACE_MATCH_MPLS_TC: if(!(pkt->__eth_type == ETH_TYPE_MPLS_UNICAST || pkt->__eth_type == ETH_TYPE_MPLS_MULTICAST )) return false;
					return __utern_compare8(it->value, &pkt->__mpls_tc);
   		case FLOWSPACE_MATCH_MPLS_BOS: if(!(pkt->__eth_type == ETH_TYPE_MPLS_UNICAST || pkt->__eth_type == ETH_TYPE_MPLS_MULTICAST )) return false;
					return __utern_compare8(it->value, (uint8_t*)&pkt->__mpls_bos);

		//ARP
   		case FLOWSPACE_MATCH_ARP_OP: if(!(pkt->__eth_type == ETH_TYPE_ARP)) return false;
   					return __utern_compare16(it->value, &pkt->__arp_opcode);
   		case FLOWSPACE_MATCH_ARP_SHA: if(!(pkt->__eth_type == ETH_TYPE_ARP)) return false;
   					return __utern_compare64(it->value, &pkt->__arp_sha);
   		case FLOWSPACE_MATCH_ARP_SPA: if(!(pkt->__eth_type == ETH_TYPE_ARP)) return false;
					return __utern_compare32(it->value, &pkt->__arp_spa);
   		case FLOWSPACE_MATCH_ARP_THA: if(!(pkt->__eth_type == ETH_TYPE_ARP)) return false;
   					return __utern_compare64(it->value, &pkt->__arp_tha);
   		case FLOWSPACE_MATCH_ARP_TPA: if(!(pkt->__eth_type == ETH_TYPE_ARP)) return false;
					return __utern_compare32(it->value, &pkt->__arp_tpa);

		//NW (OF1.0 only)
   		case FLOWSPACE_MATCH_NW_PROTO: if(!(pkt->__eth_type == ETH_TYPE_IPV4 || pkt->__eth_type == ETH_TYPE_IPV6 || pkt->__eth_type == ETH_TYPE_ARP || (pkt->__eth_type == ETH_TYPE_PPPOE_SESSION && (pkt->__ppp_proto == PPP_PROTO_IP4 || pkt->__ppp_proto == PPP_PROTO_IP6) ))) return false;
					if(pkt->__eth_type == ETH_TYPE_ARP){
						uint8_t *low_byte = ((uint8_t*)&(pkt->__arp_opcode));
						return __utern_compare8(it->value, ++low_byte);
					}
					else
						return __utern_compare8(it->value, &pkt->__ip_proto);

   		case FLOWSPACE_MATCH_NW_SRC:	if((pkt->__eth_type == ETH_TYPE_IPV4 || (pkt->__eth_type == ETH_TYPE_PPPOE_SESSION && pkt->__ppp_proto == PPP_PROTO_IP4 )))
						return __utern_compare32(it->value, &pkt->__ipv4_src);
					if(pkt->__eth_type == ETH_TYPE_ARP)
						return __utern_compare32(it->value, &pkt->__arp_spa);
					return false;
   		case FLOWSPACE_MATCH_NW_DST:	if((pkt->__eth_type == ETH_TYPE_IPV4 ||(pkt->__eth_type == ETH_TYPE_PPPOE_SESSION && pkt->__ppp_proto == PPP_PROTO_IP4 )))
						return __utern_compare32(it->value, &pkt->__ipv4_dst);
					if(pkt->__eth_type == ETH_TYPE_ARP)
						return __utern_compare32(it->value, &pkt->__arp_tpa);
					return false;
		//IP
   		case FLOWSPACE_MATCH_IP_PROTO: if(!(pkt->__eth_type == ETH_TYPE_IPV4 || pkt->__eth_type == ETH_TYPE_IPV6 || (pkt->__eth_type == ETH_TYPE_PPPOE_SESSION && (pkt->__ppp_proto == PPP_PROTO_IP4 || pkt->__ppp_proto == PPP_PROTO_IP6) ))) return false;
					return __utern_compare8(it->value, &pkt->__ip_proto);
		case FLOWSPACE_MATCH_IP_ECN: if(!(pkt->__eth_type == ETH_TYPE_IPV4 || pkt->__eth_type == ETH_TYPE_IPV6 || (pkt->__eth_type == ETH_TYPE_PPPOE_SESSION && pkt->__ppp_proto == PPP_PROTO_IP4 ))) return false; //NOTE PPP_PROTO_IP6
					return __utern_compare8(it->value, &pkt->__ip_ecn);

		case FLOWSPACE_MATCH_IP_DSCP: if(!(pkt->__eth_type == ETH_TYPE_IPV4 || pkt->__eth_type == ETH_TYPE_IPV6 || (pkt->__eth_type == ETH_TYPE_PPPOE_SESSION && pkt->__ppp_proto == PPP_PROTO_IP4 ))) return false; //NOTE PPP_PROTO_IP6
					return __utern_compare8(it->value, &pkt->__ip_dscp);

		//IPv4
   		case FLOWSPACE_MATCH_IPV4_SRC: if(!(pkt->__eth_type == ETH_TYPE_IPV4 || (pkt->__eth_type == ETH_TYPE_PPPOE_SESSION && pkt->__ppp_proto == PPP_PROTO_IP4 ))) return false;
					return __utern_compare32(it->value, &pkt->__ipv4_src);
   		case FLOWSPACE_MATCH_IPV4_DST:if(!(pkt->__eth_type == ETH_TYPE_IPV4 ||(pkt->__eth_type == ETH_TYPE_PPPOE_SESSION && pkt->__ppp_proto == PPP_PROTO_IP4 ))) return false;
					return __utern_compare32(it->value, &pkt->__ipv4_dst);

		//TCP
   		case FLOWSPACE_MATCH_TCP_SRC: if(!(pkt->__ip_proto == IP_PROTO_TCP)) return false;
					return __utern_compare16(it->value, &pkt->__tcp_src);
   		case FLOWSPACE_MATCH_TCP_DST: if(!(pkt->__ip_proto == IP_PROTO_TCP)) return false;
					return __utern_compare16(it->value, &pkt->__tcp_dst);

		//UDP
   		case FLOWSPACE_MATCH_UDP_SRC: if(!(pkt->__ip_proto == IP_PROTO_UDP)) return false;
					return __utern_compare16(it->value, &pkt->__udp_src);
   		case FLOWSPACE_MATCH_UDP_DST: if(!(pkt->__ip_proto == IP_PROTO_UDP)) return false;
					return __utern_compare16(it->value, &pkt->__udp_dst);
		//SCTP
   		case FLOWSPACE_MATCH_SCTP_SRC: if(!(pkt->__ip_proto == IP_PROTO_SCTP)) return false;
					return __utern_compare16(it->value, &pkt->__tcp_src);
   		case FLOWSPACE_MATCH_SCTP_DST: if(!(pkt->__ip_proto == IP_PROTO_SCTP)) return false;
					return __utern_compare16(it->value, &pkt->__tcp_dst);

		//TP (OF1.0 only)
   		case FLOWSPACE_MATCH_TP_SRC: if((pkt->__ip_proto == IP_PROTO_TCP))
						return __utern_compare16(it->value, &pkt->__tcp_src);
   					if((pkt->__ip_proto == IP_PROTO_UDP))
						return __utern_compare16(it->value, &pkt->__udp_src);
					if((pkt->__ip_proto == IP_PROTO_ICMPV4)){
						uint8_t two_byte[2] = {0,pkt->__icmpv4_type};
						return __utern_compare16(it->value, (uint16_t*)&two_byte);
					}
					return false;

   		case FLOWSPACE_MATCH_TP_DST: if((pkt->__ip_proto == IP_PROTO_TCP))
						return __utern_compare16(it->value, &pkt->__tcp_dst);
   					if((pkt->__ip_proto == IP_PROTO_UDP))
						return __utern_compare16(it->value, &pkt->__udp_dst);
					if((pkt->__ip_proto == IP_PROTO_ICMPV4)){
						uint8_t two_byte[2] = {0,pkt->__icmpv4_code};
						return __utern_compare16(it->value, (uint16_t*)&two_byte);
					}
					return false;

		//ICMPv4
		case FLOWSPACE_MATCH_ICMPV4_TYPE: if(!(pkt->__ip_proto == IP_PROTO_ICMPV4)) return false;
					return __utern_compare8(it->value, &pkt->__icmpv4_type);
   		case FLOWSPACE_MATCH_ICMPV4_CODE: if(!(pkt->__ip_proto == IP_PROTO_ICMPV4)) return false;
					return __utern_compare8(it->value, &pkt->__icmpv4_code);

		//IPv6
		case FLOWSPACE_MATCH_IPV6_SRC: if(!(pkt->__eth_type == ETH_TYPE_IPV6 || (pkt->__eth_type == ETH_TYPE_PPPOE_SESSION && pkt->__ppp_proto == PPP_PROTO_IP6 ))) return false;
					return __utern_compare128(it->value, &pkt->__ipv6_src);
		case FLOWSPACE_MATCH_IPV6_DST: if(!(pkt->__eth_type == ETH_TYPE_IPV6 || (pkt->__eth_type == ETH_TYPE_PPPOE_SESSION && pkt->__ppp_proto == PPP_PROTO_IP6 ))) return false;
					return __utern_compare128(it->value, &pkt->__ipv6_dst);
		case FLOWSPACE_MATCH_IPV6_FLABEL: if(!(pkt->__eth_type == ETH_TYPE_IPV6 || (pkt->__eth_type == ETH_TYPE_PPPOE_SESSION && pkt->__ppp_proto == PPP_PROTO_IP6 ))) return false;
					return __utern_compare64(it->value, &pkt->__ipv6_flabel);
		case FLOWSPACE_MATCH_IPV6_ND_TARGET: if(!(pkt->__ip_proto == IP_PROTO_ICMPV6)) return false;
					return __utern_compare128(it->value, &pkt->__ipv6_nd_target);
		case FLOWSPACE_MATCH_IPV6_ND_SLL: if(!(pkt->__ip_proto == IP_PROTO_ICMPV6 && pkt->__ipv6_nd_sll)) return false; //NOTE OPTION SLL active
					return __utern_compare64(it->value, &pkt->__ipv6_nd_sll);
		case FLOWSPACE_MATCH_IPV6_ND_TLL: if(!(pkt->__ip_proto == IP_PROTO_ICMPV6 && pkt->__ipv6_nd_tll)) return false; //NOTE OPTION TLL active
					return __utern_compare64(it->value, &pkt->__ipv6_nd_tll);
		case FLOWSPACE_MATCH_IPV6_EXTHDR: //TODO not yet implemented.
			return false;
			break;

		//ICMPv6
		case FLOWSPACE_MATCH_ICMPV6_TYPE: if(!(pkt->__ip_proto == IP_PROTO_ICMPV6)) return false;
					return __utern_compare8(it->value, &pkt->__icmpv6_type);
		case FLOWSPACE_MATCH_ICMPV6_CODE: if(!(pkt->__ip_proto == IP_PROTO_ICMPV6 )) return false;
					return __utern_compare8(it->value, &pkt->__icmpv6_code);

		//PPPoE related extensions
   		case FLOWSPACE_MATCH_PPPOE_CODE: if(!(pkt->__eth_type == ETH_TYPE_PPPOE_DISCOVERY || pkt->__eth_type == ETH_TYPE_PPPOE_SESSION )) return false;
						return __utern_compare8(it->value, &pkt->__pppoe_code);
   		case FLOWSPACE_MATCH_PPPOE_TYPE: if(!(pkt->__eth_type == ETH_TYPE_PPPOE_DISCOVERY || pkt->__eth_type == ETH_TYPE_PPPOE_SESSION )) return false;
						return __utern_compare8(it->value, &pkt->__pppoe_type);
   		case FLOWSPACE_MATCH_PPPOE_SID: if(!(pkt->__eth_type == ETH_TYPE_PPPOE_DISCOVERY || pkt->__eth_type == ETH_TYPE_PPPOE_SESSION )) return false;
						return __utern_compare16(it->value, &pkt->__pppoe_sid);

		//PPP
   		case FLOWSPACE_MATCH_PPP_PROT: if(!(pkt->__eth_type == ETH_TYPE_PPPOE_SESSION )) return false;
						return __utern_compare16(it->value, &pkt->__ppp_proto);

		//PBB
   		case FLOWSPACE_MATCH_PBB_ISID: if(pkt->__eth_type == ETH_TYPE_PBB) return false;
						return __utern_compare32(it->value, &pkt->__pbb_isid);
	 	//TUNNEL id
   		case FLOWSPACE_MATCH_TUNNEL_ID: return __utern_compare64(it->value, &pkt->__tunnel_id);

		//GTP
   		case FLOWSPACE_MATCH_GTP_MSG_TYPE: if (!(pkt->__ip_proto == IP_PROTO_UDP || pkt->__udp_dst == UDP_DST_PORT_GTPU)) return false;
   						return __utern_compare8(it->value, &pkt->__gtp_msg_type);
   		case FLOWSPACE_MATCH_GTP_TEID: if (!(pkt->__ip_proto == IP_PROTO_UDP || pkt->__udp_dst == UDP_DST_PORT_GTPU)) return false;
   						return __utern_compare32(it->value, &pkt->__gtp_teid);
		case FLOWSPACE_MATCH_MAX:
				break;
		//Add more here ...
		//Warning: NEVER add a default clause
	}

	assert(0);
	return NULL;
}


