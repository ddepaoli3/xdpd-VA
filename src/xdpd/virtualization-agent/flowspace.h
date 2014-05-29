/*
 * flowspace.h
 *
 *  @author Daniel Depaoli <daniel.depaoli (at) create-net.org>
 */


#ifndef FLOWSPACE_H_
#define FLOWSPACE_H_

#include "slice.h"

#include "rofl/common/openflow/cofmatch.h"

typedef struct utern_flowspace{
	utern_type_t type;
	wrap_uint_t value;
	wrap_uint_t mask;
} utern_flowspace_t;

/**
 * Struct copied from of1x_match_
 */
typedef enum{
	/* phy */
	FLOWSPACE_MATCH_IN_PORT,		/* Switch input port. */		//required
	FLOWSPACE_MATCH_IN_PHY_PORT,	/* Switch physical input port. */  //!< FLOWSPACE_MATCH_IN_PHY_PORT

	/* metadata */
	FLOWSPACE_MATCH_METADATA,		/* Metadata passed between tables. *///!< FLOWSPACE_MATCH_METADATA

	/* eth */
	FLOWSPACE_MATCH_ETH_DST,		/* Ethernet destination address. */	//required
	FLOWSPACE_MATCH_ETH_SRC,		/* Ethernet source address. */		//required
	FLOWSPACE_MATCH_ETH_TYPE,		/* Ethernet frame type. */		//required
	FLOWSPACE_MATCH_VLAN_VID,		/* VLAN id. */                       //!< FLOWSPACE_MATCH_VLAN_VID
	FLOWSPACE_MATCH_VLAN_PCP,		/* VLAN priority. */                 //!< FLOWSPACE_MATCH_VLAN_PCP

	/* mpls */
	FLOWSPACE_MATCH_MPLS_LABEL,		/* MPLS label. */                  //!< FLOWSPACE_MATCH_MPLS_LABEL
	FLOWSPACE_MATCH_MPLS_TC,		/* MPLS TC. */                        //!< FLOWSPACE_MATCH_MPLS_TC
	FLOWSPACE_MATCH_MPLS_BOS,		/* MPLS BoS flag. */                 //!< FLOWSPACE_MATCH_MPLS_BOS

	/* arp */
	FLOWSPACE_MATCH_ARP_OP,			/* ARP opcode. */                     //!< FLOWSPACE_MATCH_ARP_OP
	FLOWSPACE_MATCH_ARP_SPA,		/* ARP source IPv4 address. */        //!< FLOWSPACE_MATCH_ARP_SPA
	FLOWSPACE_MATCH_ARP_TPA,		/* ARP target IPv4 address. */        //!< FLOWSPACE_MATCH_ARP_TPA
	FLOWSPACE_MATCH_ARP_SHA,		/* ARP source hardware address. */    //!< FLOWSPACE_MATCH_ARP_SHA
	FLOWSPACE_MATCH_ARP_THA,		/* ARP target hardware address. */    //!< FLOWSPACE_MATCH_ARP_THA

	/* network layer */
	FLOWSPACE_MATCH_NW_PROTO,		/* Network layer Ip proto/arp code. OF10 ONLY */	//required
	FLOWSPACE_MATCH_NW_SRC,			/* Network layer source address. OF10 ONLY */		//required
	FLOWSPACE_MATCH_NW_DST,			/* Network layer destination address. OF10 ONLY */	//required

	/* ipv4 */
	FLOWSPACE_MATCH_IP_DSCP,		/* IP DSCP (6 bits in ToS field). */  //!< FLOWSPACE_MATCH_IP_DSCP
	FLOWSPACE_MATCH_IP_ECN,			/* IP ECN (2 bits in ToS field). */   //!< FLOWSPACE_MATCH_IP_ECN
	FLOWSPACE_MATCH_IP_PROTO,		/* IP protocol. */			//required
	FLOWSPACE_MATCH_IPV4_SRC,		/* IPv4 source address. */		//required
	FLOWSPACE_MATCH_IPV4_DST,		/* IPv4 destination address. */		//required

	/* ipv6 */
	FLOWSPACE_MATCH_IPV6_SRC,		/* IPv6 source address. */		//required
	FLOWSPACE_MATCH_IPV6_DST,		/* IPv6 destination address. */		//required
	FLOWSPACE_MATCH_IPV6_FLABEL,	/* IPv6 Flow Label */              //!< FLOWSPACE_MATCH_IPV6_FLABEL
	FLOWSPACE_MATCH_ICMPV6_TYPE,	/* ICMPv6 type. */                 //!< FLOWSPACE_MATCH_ICMPV6_TYPE
	FLOWSPACE_MATCH_ICMPV6_CODE,	/* ICMPv6 code. */                 //!< FLOWSPACE_MATCH_ICMPV6_CODE
	FLOWSPACE_MATCH_IPV6_ND_TARGET,	/* Target address for ND. */    //!< FLOWSPACE_MATCH_IPV6_ND_TARGET
	FLOWSPACE_MATCH_IPV6_ND_SLL,	/* Source link-layer for ND. */    //!< FLOWSPACE_MATCH_IPV6_ND_SLL
	FLOWSPACE_MATCH_IPV6_ND_TLL,	/* Target link-layer for ND. */    //!< FLOWSPACE_MATCH_IPV6_ND_TLL
	FLOWSPACE_MATCH_IPV6_EXTHDR,	/* Extension header */             //!< FLOWSPACE_MATCH_IPV6_EXTHDR

	/* transport */
	FLOWSPACE_MATCH_TP_SRC,			/* TCP/UDP source port. OF10 ONLY */	//required
	FLOWSPACE_MATCH_TP_DST,			/* TCP/UDP dest port. OF10 ONLY */	//required
	FLOWSPACE_MATCH_TCP_SRC,		/* TCP source port. */			//required
	FLOWSPACE_MATCH_TCP_DST,		/* TCP destination port. */		//required
	FLOWSPACE_MATCH_UDP_SRC,	    /* UDP source port. */			//required
	FLOWSPACE_MATCH_UDP_DST,		/* UDP destination port. */		//required
	FLOWSPACE_MATCH_SCTP_SRC,		/* SCTP source port. */              //!< FLOWSPACE_MATCH_SCTP_SRC
	FLOWSPACE_MATCH_SCTP_DST,		/* SCTP destination port. */         //!< FLOWSPACE_MATCH_SCTP_DST
	FLOWSPACE_MATCH_ICMPV4_TYPE,	/* ICMP type. */                   //!< FLOWSPACE_MATCH_ICMPV4_TYPE
	FLOWSPACE_MATCH_ICMPV4_CODE,	/* ICMP code. */                   //!< FLOWSPACE_MATCH_ICMPV4_CODE

	/* other */
	FLOWSPACE_MATCH_PBB_ISID,                                       //!< FLOWSPACE_MATCH_PBB_ISID
	FLOWSPACE_MATCH_TUNNEL_ID,                                      //!< FLOWSPACE_MATCH_TUNNEL_ID

	/********************************/
	/**** Extensions out of spec ****/
	/********************************/

	/* PPP/PPPoE related extensions */
	FLOWSPACE_MATCH_PPPOE_CODE,		/* PPPoE code */                   //!< FLOWSPACE_MATCH_PPPOE_CODE
	FLOWSPACE_MATCH_PPPOE_TYPE,		/* PPPoE type */                   //!< FLOWSPACE_MATCH_PPPOE_TYPE
	FLOWSPACE_MATCH_PPPOE_SID,		/* PPPoE session id */              //!< FLOWSPACE_MATCH_PPPOE_SID
	FLOWSPACE_MATCH_PPP_PROT,		/* PPP protocol */                   //!< FLOWSPACE_MATCH_PPP_PROT

	/* GTP related extensions */
	FLOWSPACE_MATCH_GTP_MSG_TYPE,	/* GTP message type */            //!< FLOWSPACE_MATCH_GTP_MSG_TYPE
	FLOWSPACE_MATCH_GTP_TEID,		/* GTP teid */                       //!< FLOWSPACE_MATCH_GTP_TEID

	/* max value */
	FLOWSPACE_MATCH_MAX,                                            //!< FLOWSPACE_MATCH_MAX
}flowspace_match_type;

typedef struct flowspace_match{

	//Type
	flowspace_match_type type;

	//Ternary value
	utern_t* value;

}flowspace_match_t;


typedef struct flowspace_struct{

	uint32_t priority;

	//TODO:[VA] instead list of struct use double linked list
	//Previous entry
	//struct of1x_flow_entry* prev;

	//Next entry
	//struct of1x_flow_entry* next;

	//Matches
	std::list<flowspace_match_t*> match_list;

	// Name of slice to which flowspace belongs to
	std::string slice;

	// flowspace name
	std::string name;

}flowspace_struct_t;



#endif /* FLOWSPACE_H_ */
