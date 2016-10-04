/*
 * Copyright(C) 2016 Simon Schmidt
 * 
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */
#include <ppe/icmp6.h>
//#include <ppe/ipv6.h>
#include <ppe/icmp.h>
#include <ppe/packing.h>
#include <ppe/stdint.h>
#include <ppe/errornum.h>
#include <ppe/endianess.h>

/*
 *    IPv6PacketHeader
 * @brief Ethernet-Frame Header
 */
typedef net_struct_begin{
	/*
	 * version | Traffic Class | Flow Label
	 */
	uint32_t verTcFlowLabel;
	uint16_t payloadLength;
	uint8_t nextHeader;
	uint8_t hopLimit;
	uint8_t srcIPv6Addr[16];
	uint8_t dstIPv6Addr[16];
} net_struct_end IPv6PacketHeader;

typedef net_struct_begin{
	uint8_t content[16];
} net_struct_end IPv6Addr;

typedef void* Pointer;

#include "icmp6_priv.h"

enum{
	ICMPv6_MTU = IPv6_DEFAULT_MTU - (sizeof(IPv6PacketHeader)+8),
};

int ppe_createDatagramResponse_icmp6(ppeBuffer *packet, ICMPv6_Arguments *args){
	Pointer beginPacket,endPacket;
	uintptr_t length;
	
	beginPacket = packet->position;
	endPacket   = packet->limit;
	length      = endPacket-beginPacket;
	
	if(ICMPv6_MTU < length){
		endPacket = beginPacket+ICMPv6_MTU;
		packet->limit = endPacket;
	}
	
	/*
	 * Prepend 4 bytes Rest-Of-Header to the packet.
	 */
	beginPacket-=4;
	
	/*
	 * Bounds-Check the new Position.
	 */
	if(beginPacket < packet->begin) return ERROR_BUFFER_OVERFLOW;
	
	/*
	 * Add Rest-Of-Header field.
	 */
	*((uint32_t*)beginPacket) = args->restOfHeader;
	
	/*
	 * Update the Packet's bounds.
	 */
	packet->position = beginPacket;
	
	/*
	 * Create the ICMP packet.
	 */
	return ppe_createPacket_icmp(packet,&(args->icmp));
}

int ppe_parsePacket_icmp6(ppeBuffer *packet, ICMPv6_Arguments *info){
	int result;
	uint8_t type,code;
	uint32_t *content;
	Pointer beginPacket,endPayload,endPacket;
	IPv6PacketHeader *ipHeader;

	result = ppe_parsePacket_icmp(packet,&(info->icmp));
	if(result) return result;
	
	type = info->inputType = info->icmp.type;
	code = info->inputCode = info->icmp.code;
	
	switch( type ){
	case ICMPv6_DEST_UNREACH:
		info->payloadType = ICMPv6_Pld_IpHeader;
		info->messageType = ICMPv6_Msg_Notification;
		switch( code ){
		
		/*
		 * Everything that indicates an Unreachable Network.
		 */
		case ICMPv6_DEST_UNREACH_NO_ROUTE:      /* no route to destination */
		case ICMPv6_DEST_UNREACH_BEYOND_SCOPE:  /* beyond scope of source address */
		case ICMPv6_DEST_UNREACH_ROUTE_REJECT:  /* reject route to destination */
			info->mesgMeaning = ICMPv6_Mng_UnreachableNet;
			break;
		case ICMPv6_DEST_UNREACH_PROHIB: /* communication with destination administratively prohibited */
		case ICMPv6_DEST_UNREACH_HOST:   /* address unreachable */
			info->mesgMeaning = ICMPv6_Mng_UnreachableHost;
			break;
		case ICMPv6_DEST_UNREACH_PORT:  /* port unreachable */
			info->mesgMeaning = ICMPv6_Mng_UnreachablePort;
			break;
		case ICMPv6_DEST_UNREACH_POLICY_FAIL:
			info->mesgMeaning = ICMPv6_Mng_UnreachablePolicyFail;
			break;
		case ICMPv6_DEST_UNREACH_HEADER:
			info->mesgMeaning = ICMPv6_Mng_UnreachablePacketHeader;
			break;
		default:
			info->mesgMeaning = ICMPv6_Mng_None;
		}
		break;
	case ICMPv6_PACKET_TOO_BIG:
		info->payloadType = ICMPv6_Pld_IpHeader;
		info->messageType = ICMPv6_Msg_Notification;
		info->messageType = ICMPv6_Mng_MessageSizeTooBig;
		break;
	case ICMPv6_TIMXCEED:
		info->payloadType = ICMPv6_Pld_IpHeader;
		info->messageType = ICMPv6_Msg_Notification;
		info->messageType = ICMPv6_Mng_TimeExeeded;
		break;
	case ICMPv6_PARAM_PROBLEM:
		info->payloadType = ICMPv6_Pld_IpHeader;
		info->messageType = ICMPv6_Msg_Notification;
		switch( code ) {
		case ICMPv6_PARAM_PROBLEM_HEADER:
			info->mesgMeaning = ICMPv6_Mng_ParameterProblems;
			break;
		case ICMPv6_PARAM_PROBLEM_NEXT_HEADER:
			info->mesgMeaning = ICMPv6_Mng_UnreachableProtocol;
			break;
		case ICMPv6_PARAM_PROBLEM_OPTION:
			info->mesgMeaning = ICMPv6_Mng_ParameterProblems;
			break;
		default:
			info->mesgMeaning = ICMPv6_Mng_ParameterProblems;
		}
		break;
	
	/* ICMPv6 echo */
	case ICMPv6_ECHO_REQUEST:
		info->payloadType = ICMPv6_Pld_Echo;
		info->messageType = ICMPv6_Msg_Request;
		info->mesgMeaning = ICMPv6_Mng_Echo;
		info->icmp.type   = ICMPv6_ECHO_REPLY;
		break;
	case ICMPv6_ECHO_REPLY:
		info->payloadType = ICMPv6_Pld_Echo;
		info->messageType = ICMPv6_Msg_Response;
		info->mesgMeaning = ICMPv6_Mng_Echo;
		break;
	
	/*
	 * TODO: We still need to implement MLD and NDP correctly.
	 */
	
	/* - Multicast Listener Discovery */
	case ICMPv6_MLD_QUERY:
		info->payloadType = ICMPv6_Pld_Echo;
		info->messageType = ICMPv6_Msg_Request;
		info->mesgMeaning = ICMPv6_Mng_Echo;
		info->icmp.type   = ICMPv6_MLD_REPORT;
		break;
	case ICMPv6_MLD_REPORT:
		info->payloadType = ICMPv6_Pld_Echo;
		info->messageType = ICMPv6_Msg_Response;
		info->mesgMeaning = ICMPv6_Mng_Echo;
		break;
	case ICMPv6_MLD_DONE:
		info->payloadType = ICMPv6_Pld_Echo;
		info->messageType = ICMPv6_Msg_Notification;
		info->mesgMeaning = ICMPv6_Mng_Echo;
		break;
	
	/* Neighbor Discovery Protocol */
	case ICMPv6_NDP_ROUTER_SOLICIT:
		info->payloadType = ICMPv6_Pld_Echo;
		info->messageType = ICMPv6_Msg_Notification;
		info->mesgMeaning = ICMPv6_Mng_RouterSolicitation;
		break;
	case ICMPv6_NDP_ROUTER_ADVERT:
		info->payloadType = ICMPv6_Pld_RouterAdvertisement;
		info->messageType = ICMPv6_Msg_Notification;
		info->mesgMeaning = ICMPv6_Mng_RouterAdvertisement;
		break;
	case ICMPv6_NDP_NEIGHBOR_SOLICIT:
		info->payloadType = ICMPv6_Pld_SingleAddress;
		info->messageType = ICMPv6_Msg_Notification;
		info->mesgMeaning = ICMPv6_Mng_NeighborSolicitation;
		break;
	case ICMPv6_NDP_NEIGHBOR_ADVERT:
		info->payloadType = ICMPv6_Pld_SingleAddress;
		info->messageType = ICMPv6_Msg_Notification;
		info->mesgMeaning = ICMPv6_Mng_NeighborAdvertisement;
		break;
	case ICMPv6_NDP_REDIRECT:
		info->payloadType = ICMPv6_Pld_DualAddress;
		info->messageType = ICMPv6_Msg_Notification;
		info->mesgMeaning = ICMPv6_Mng_Redirect;
		break;
	}

	beginPacket = packet->position;
	endPacket = packet->limit;

	switch( info->payloadType ) {
	case ICMPv6_Pld_Echo:

		endPayload = beginPacket+4;
		if(endPayload > endPacket) return ERROR_BUFFER_OVERFLOW;

		content             =  beginPacket;
		info->restOfHeader  =  content[0];
		break;
	case ICMPv6_Pld_IpHeader:

		endPayload = beginPacket+4;
		if((endPayload+sizeof(IPv6PacketHeader)) > endPacket) return ERROR_BUFFER_OVERFLOW;
		ipHeader = endPayload;

		content             =  beginPacket;
		info->restOfHeader  =  content[0];

		*((IPv6Addr*)info->ipAddress[0]) = *((IPv6Addr*)ipHeader->srcIPv6Addr);
		*((IPv6Addr*)info->ipAddress[1]) = *((IPv6Addr*)ipHeader->dstIPv6Addr);

		packet->position    =  endPayload;
		break;
	case ICMPv6_Pld_RouterAdvertisement:
		endPayload = beginPacket+12;
		if(endPayload > endPacket) return ERROR_BUFFER_OVERFLOW;

		content              =  beginPacket;
		info->restOfHeader   =  decBE32(content[0]); /* We want the options in native byte-order */
		info->reachTimeout   =  decBE32(content[1]);
		info->resolvTimeout  =  decBE32(content[2]);
		info->routerLifeTime = info->restOfHeader&0xFFFF;
		info->advFlags       = (info->restOfHeader>>16)&0xFF;
		info->hopLimit       = (info->restOfHeader>>24)&0xFF;

		packet->position     =  endPayload;
		break;
	case ICMPv6_Pld_DualAddress:
		endPayload = beginPacket+4;
		if((endPayload+(sizeof(IPv6Addr)*2)) > endPacket) return ERROR_BUFFER_OVERFLOW;

		*((IPv6Addr*)info->ipAddress[1]) = ((IPv6Addr*)endPayload)[1];

	case ICMPv6_Pld_SingleAddress:
		endPayload = beginPacket+4;
		if((endPayload+sizeof(IPv6Addr)) > endPacket) return ERROR_BUFFER_OVERFLOW;

		content             =  beginPacket;
		info->restOfHeader  =  decBE32(content[0]); /* We want the options in native byte-order */

		*((IPv6Addr*)info->ipAddress[0]) = *((IPv6Addr*)endPayload);
		packet->position    =  endPayload;
		break;
	}
	
	return 0;
}

