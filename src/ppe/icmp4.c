/*
 * Copyright(C) 2015-2016 Simon Schmidt
 * 
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */
#include <ppe/icmp4.h>
//#include <ppe/ipv4.h>
#include <ppe/icmp.h>
#include <ppe/packing.h>
#include <ppe/stdint.h>
#include <ppe/errornum.h>
#include <ppe/endianess.h>

/*
 * FNET's ICMPv4 headers (Apache 2.0 licensed).
 */
#include "icmp4_priv.h"

typedef void* Pointer;
typedef uint8_t* BytePtr;

int ppe_createDatagramResponse_icmp4(ppeBuffer *packet, ICMPv4_Arguments *args){
	Pointer beginPacket,endPacket;
	
	beginPacket = packet->position;
	
	/*
	 * Extract the IHL of the IP packet, calculate the IP header Length,
	 * and add the first 8 bytes of the payload.
	 */
	int length  =  (0xf&*((BytePtr)beginPacket)) * 4;
	length     +=  8;
	endPacket   =  beginPacket+length;
	
	
	if(endPacket < packet->limit) packet->limit = endPacket;
	
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


int ppe_createTimeStamp_icmp4(ppeBuffer *packet, ICMPv4_Arguments *args){
	Pointer beginPacket,endPacket;
	uint32_t* content;
	
	beginPacket = packet->position;
	
	endPacket = beginPacket+16;
	
	
	/*
	 * Bounds-Check the new Position.
	 */
	if(endPacket > packet->end) return ERROR_BUFFER_OVERFLOW;
	
	content    = beginPacket;
	content[0] = args->restOfHeader       ;
	content[1] = args->originateTimestamp ;
	content[2] = args->receiveTimestamp   ;
	content[3] = args->transmitTimestamp  ;
	
	/*
	 * Update the Packet's bounds.
	 */
	packet->limit = endPacket;
	
	/*
	 * Create the ICMP packet.
	 */
	return ppe_createPacket_icmp(packet,&(args->icmp));
}


int ppe_createAddressMask_icmp4(ppeBuffer *packet, ICMPv4_Arguments *args){
	Pointer beginPacket,endPacket;
	uint32_t* content;

	beginPacket = packet->position;

	endPacket = beginPacket+8;

	/*
	 * Bounds-Check the new Position.
	 */
	if(endPacket > packet->end) return ERROR_BUFFER_OVERFLOW;

	content    = beginPacket;
	content[0] = args->restOfHeader ;
	content[1] = args->addressMask  ;

	/*
	 * Update the Packet's bounds.
	 */
	packet->limit = endPacket;

	/*
	 * Create the ICMP packet.
	 */
	return ppe_createPacket_icmp(packet,&(args->icmp));
}



int ppe_parsePacket_icmp4(ppeBuffer *packet, ICMPv4_Arguments *info){
	int result;
	uint8_t type,code;
	uint32_t* content;
	uint16_t* portPtr;
	int ihl;
	//ppeBuffer tempPkt;
	Pointer beginPacket,endPayload,endPacket;
	result = ppe_parsePacket_icmp(packet,&(info->icmp));
	if(result) return result;
	
	type = info->inputType = info->icmp.type;
	code = info->inputCode = info->icmp.code;
	
	switch( type ){
	case FNET_ICMP_ECHOREPLY:
		info->payloadType = ICMPv4_Pld_Echo;
		info->messageType = ICMPv4_Msg_Response;
		info->mesgMeaning = ICMPv4_Mng_Echo;
		break;
	case FNET_ICMP_ECHO:
		info->payloadType = ICMPv4_Pld_Echo;
		info->messageType = ICMPv4_Msg_Request;
		info->mesgMeaning = ICMPv4_Mng_Echo;
		info->icmp.type = FNET_ICMP_ECHOREPLY;
		break;
	case FNET_ICMP_UNREACHABLE:
		info->payloadType = ICMPv4_Pld_IpHeader;
		info->messageType = ICMPv4_Msg_Notification;
		switch( code ){
		
		/*
		 * Everything that indicates an Unreachable Network.
		 */
		case FNET_ICMP_UNREACHABLE_NET:
		case FNET_ICMP_UNREACHABLE_NET_UNKNOWN:
		case FNET_ICMP_UNREACHABLE_NET_PROHIB:
		case FNET_ICMP_UNREACHABLE_TOSNET:
			info->mesgMeaning = ICMPv4_Mng_UnreachableNet;
			break;
		
		/*
		 * Everything that indicates an Unreachable Host.
		 */
		case FNET_ICMP_UNREACHABLE_HOST:
		case FNET_ICMP_UNREACHABLE_HOST_UNKNOWN:
		case FNET_ICMP_UNREACHABLE_HOST_PROHIB:
		case FNET_ICMP_UNREACHABLE_TOSHOST:
			info->mesgMeaning = ICMPv4_Mng_UnreachableHost;
			break;
		
		/*
		 * Protocol unreachable error (the designated transport
		 * protocol is not supported).
		 */
		case FNET_ICMP_UNREACHABLE_PROTOCOL:
			info->mesgMeaning = ICMPv4_Mng_UnreachableProtocol;
			break;
		
		/*
		 * Port unreachable error (the designated protocol is unable
		 * to inform the host of the incoming message).
		 */
		case FNET_ICMP_UNREACHABLE_PORT:
			info->mesgMeaning = ICMPv4_Mng_UnreachablePort;
			break;
		
		/*
		 * Source route failed error.
		 */
		case FNET_ICMP_UNREACHABLE_SRCFAIL:
			info->mesgMeaning = ICMPv4_Mng_UnreachableSource;
			break;
		
		/*
		 * The datagram is too big. Packet fragmentation is required
		 * but the 'don't fragment' (DF) flag is on.
		 */
		case FNET_ICMP_UNREACHABLE_NEEDFRAG:
			info->mesgMeaning = ICMPv4_Mng_MessageSizeTooBig;
			break;
		}
		break;
	case FNET_ICMP_TSTAMP:
		info->payloadType = ICMPv4_Pld_Timestamp;
		info->messageType = ICMPv4_Msg_Request;
		info->mesgMeaning = ICMPv4_Mng_Timestamp;
		info->icmp.type = FNET_ICMP_TSTAMPREPLY;
		break;
	case FNET_ICMP_TSTAMPREPLY:
		info->payloadType = ICMPv4_Pld_Timestamp;
		info->messageType = ICMPv4_Msg_Response;
		info->mesgMeaning = ICMPv4_Mng_Timestamp;
		break;
	
	
	/*
	 * Time-to-live exceeded.
	 */
	case FNET_ICMP_TIMXCEED:
		info->payloadType = ICMPv4_Pld_IpHeader;
		info->messageType = ICMPv4_Msg_Notification;
		info->mesgMeaning = ICMPv4_Mng_TimeExeeded;
		break;
	
	/*
	 * Parameter Problem: Bad IP header.
	 */
	case FNET_ICMP_PARAMPROB:
		info->payloadType = ICMPv4_Pld_IpHeader;
		info->messageType = ICMPv4_Msg_Notification;
		info->mesgMeaning = ICMPv4_Mng_ParameterProblems;
		break;
	
	/*
	 * Source quench (congestion control).
	 */
	case FNET_ICMP_SOURCEQUENCH:
		info->payloadType = ICMPv4_Pld_IpHeader;
		info->messageType = ICMPv4_Msg_Notification;
		info->mesgMeaning = ICMPv4_Mng_ParameterProblems;
		break;
	
	case FNET_ICMP_ROUTERADVERT:
		info->payloadType = ICMPv4_Pld_RouterAdvertisement;
		info->messageType = ICMPv4_Msg_Notification;
		info->mesgMeaning = ICMPv4_Mng_RouterAdvertisement;
		break;
	case FNET_ICMP_ROUTERSOLICIT:
		info->payloadType = ICMPv4_Pld_Echo;
		info->messageType = ICMPv4_Msg_Notification;
		info->mesgMeaning = ICMPv4_Mng_RouterSolicitation;
		break;
	default:
		info->payloadType = ICMPv4_Pld_Echo;
		info->messageType = ICMPv4_Msg_Notification;
		info->mesgMeaning = ICMPv4_Mng_None;
	}
	
	beginPacket = packet->position;
	endPacket = packet->limit;
	switch( info->payloadType ) {
	case ICMPv4_Pld_Timestamp:

		endPayload = beginPacket+16;
		if(endPayload > endPacket) return ERROR_BUFFER_OVERFLOW;

		content                  =  beginPacket;
		info->restOfHeader       =  content[0];
		info->originateTimestamp =  content[1];
		info->receiveTimestamp   =  content[2];
		info->transmitTimestamp  =  content[3];
		break;

	case ICMPv4_Pld_AddressMask:

		endPayload = beginPacket+8;
		if(endPayload > endPacket) return ERROR_BUFFER_OVERFLOW;

		content             =  beginPacket;
		info->restOfHeader  =  content[0];
		info->addressMask   =  content[1];
		break;

/*
 *             Figure 1: IPv4 packet
 *
 *   0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |Version|  IHL  |   DSCP    |ECN|          Total Length         |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         Identification        |Flags|      Fragment Offset    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  Time to Live |    Protocol   |         Header Checksum       |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                       Source Address                          |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                    Destination Address                        |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *      Additionally/Optionally:
 *
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                          Options                              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     .
 *     .
 *     .
 */
	/*
	 * We are going to unpack the IP-Header. We are not going to use
	 * ppe_parsePacket_ipv4() since it wouldn't successfully verify
	 * the checksum of the IP header.
	 *
	 * Also, we are going to parse as much of the packet as possible
	 * rather than giving up and returning an ERROR_BUFFER_OVERFLOW!
	 */
	case ICMPv4_Pld_IpHeader:
		endPayload = beginPacket+4;
		if(endPayload > endPacket) return ERROR_BUFFER_OVERFLOW;

		content             =  beginPacket;
		info->restOfHeader  =  content[0];

		if((endPayload+1) > endPacket) goto pld_ip_proto;

		ihl = (0xf & *((uint8_t*)endPayload));

		if((endPayload+10) > endPacket) goto pld_ip_proto;

		info->ipProtoc      = *((uint8_t*)(endPayload+9));

		if((endPayload+20) > endPacket) goto pld_ip_address;
		info->ipAddress[0]  = content[4];
		info->ipAddress[1]  = content[5];

		portPtr = (uint16_t*)(endPayload+(ihl*4));
		if((Pointer)(&portPtr[2]) > endPacket) goto pld_ip_ports;
		info->ports[0]      = portPtr[0];
		info->ports[1]      = portPtr[1];

		goto pld_ip_end;
	pld_ip_proto:
		info->ipProtoc      = 0;
	pld_ip_address:
		info->ipAddress[0]  = 0;
		info->ipAddress[1]  = 0;
	pld_ip_ports:
		info->ports[0]      = 0;
		info->ports[1]      = 0;
	pld_ip_end:
		packet->position = endPayload;
		break;
		
	/*
	 * On those headers, don't parse the Payload;
	 */
	case ICMPv4_Pld_Echo:
	/* see https://tools.ietf.org/html/rfc1256 section 3. Message Formats */
	case ICMPv4_Pld_RouterAdvertisement:
		endPayload = beginPacket+4;
		if(endPayload > endPacket) return ERROR_BUFFER_OVERFLOW;

		content             =  beginPacket;
		info->restOfHeader  =  content[0];
		break;
	}

	return 0;
}

