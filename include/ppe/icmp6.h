/*
 * Copyright(C) 2016 Simon Schmidt
 * 
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */
#ifndef PPE_ICMP6_H
#define PPE_ICMP6_H
#include <ppe/stdint.h>
#include <ppe/buffer.h>
#include <ppe/icmp.h>

enum ICMPv6_payload{
	ICMPv6_Pld_IpHeader,
	ICMPv6_Pld_Echo,
};

enum ICMPv6_message{
	ICMPv6_Msg_Request,
	ICMPv6_Msg_Response,
	ICMPv6_Msg_Notification,
};
enum ICMPv6_meaning{
	ICMPv6_Mng_None,
	ICMPv6_Mng_Echo,
	ICMPv6_Mng_SourceQuench,
	ICMPv6_Mng_ParameterProblems,
	ICMPv6_Mng_TimeExeeded,
	ICMPv6_Mng_UnreachableNet,
	ICMPv6_Mng_UnreachableHost,
	ICMPv6_Mng_UnreachableProtocol,
	ICMPv6_Mng_UnreachablePort,
	ICMPv6_Mng_UnreachableSource,
	ICMPv6_Mng_UnreachablePolicyFail,
	ICMPv6_Mng_UnreachablePacketHeader,
	ICMPv6_Mng_MessageSizeTooBig,
	ICMPv6_Mng_RouterAdvertisement,
	ICMPv6_Mng_RouterSolicitation,
	ICMPv6_Mng_NeighborAdvertisement,
	ICMPv6_Mng_NeighborSolicitation,
	ICMPv6_Mng_Redirect,
};

typedef uint8_t ICMPv6IP[16];

typedef struct{
	ICMP_PacketInfo icmp;
	
	uint32_t restOfHeader; /* < The rest of header in network order. */
	
	/*
	 * used by ppe_parsePacket_icmp6.
	 */
	ICMPv6IP ipAddress[2];
	uint16_t ipHdrLen;
	uint8_t  ipProtoc;
	uint8_t  inputType,inputCode;
	
	enum ICMPv6_payload payloadType  : 4;
	enum ICMPv6_message messageType  : 4;
	enum ICMPv6_meaning mesgMeaning  : 5;
} ICMPv6_Arguments;

#if 0
/*
 * @brief creates an ICMPv4 Packet with IP header and 8 follow-on bytes
 * @param  packet  The Packet Buffer.
 * @param  info    Frame Informations
 * @return 0 on success, !=0 otherwise
 * 
 * This function creates an ICMPv4-packet with IP header and 8 follow-on bytes.
 */
int ppe_createDatagramResponse_icmp6(ppeBuffer *packet, ICMPv6_Arguments *args);


/*
 * @brief creates an ICMPv4 Packet with Timestamp
 * @param  packet  The Packet Buffer.
 * @param  info    Frame Informations
 * @return 0 on success, !=0 otherwise
 * 
 * This function creates an ICMPv4-packet with Timestamp.
 */
int ppe_createTimeStamp_icmp6(ppeBuffer *packet, ICMPv6_Arguments *args);


/*
 * @brief creates an ICMPv4 Packet with Address mask
 * @param  packet  The Packet Buffer.
 * @param  info    Frame Informations
 * @return 0 on success, !=0 otherwise
 * 
 * This function creates an ICMPv4-packet with Address mask.
 */
int ppe_createAddressMask_icmp6(ppeBuffer *packet, ICMPv6_Arguments *args);
#endif

/*
 * @brief parses an ARP Packet
 * @param  packet  The Packet Buffer.
 * @param  info    Frame Informations
 * @return 0 on success, !=0 otherwise
 * 
 * This function parses an ICMPv4-packet and extracts all header informations.
 */
int ppe_parsePacket_icmp6(ppeBuffer *packet, ICMPv6_Arguments *info);



#endif


