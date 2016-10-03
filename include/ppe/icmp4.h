/*
 * Copyright(C) 2016 Simon Schmidt
 * 
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */
#ifndef PPE_ICMP4_H
#define PPE_ICMP4_H
#include <ppe/stdint.h>
#include <ppe/buffer.h>
#include <ppe/icmp.h>

enum ICMPv4_payload{
	ICMPv4_Pld_Timestamp,
	ICMPv4_Pld_AddressMask,
	ICMPv4_Pld_IpHeader,
	ICMPv4_Pld_Echo,
	ICMPv4_Pld_RouterAdvertisement,
};

enum ICMPv4_message{
	ICMPv4_Msg_Request,
	ICMPv4_Msg_Response,
	ICMPv4_Msg_Notification,
};
enum ICMPv4_meaning{
	ICMPv4_Mng_None,
	ICMPv4_Mng_Timestamp,
	ICMPv4_Mng_AddressMask,
	ICMPv4_Mng_Echo,
	ICMPv4_Mng_SourceQuench,
	ICMPv4_Mng_ParameterProblems,
	ICMPv4_Mng_TimeExeeded,
	ICMPv4_Mng_UnreachableNet,
	ICMPv4_Mng_UnreachableHost,
	ICMPv4_Mng_UnreachableProtocol,
	ICMPv4_Mng_UnreachablePort,
	ICMPv4_Mng_UnreachableSource,
	ICMPv4_Mng_MessageSizeTooBig,
	ICMPv4_Mng_RouterAdvertisement,
	ICMPv4_Mng_RouterSolicitation,
};

enum ICMPv4_IpValidityLevel {
	ICMPv4_Ivl_None = 0,
	ICMPv4_Ivl_Protoc = 1,
	ICMPv4_Ivl_Address = 2,
	ICMPv4_Ivl_Ports   = 3,
};

typedef struct{
	ICMP_PacketInfo icmp;
	
	uint32_t restOfHeader; /* < The rest of header in network order. */
	union{
		uint32_t originateTimestamp;
		uint32_t addressMask;
	};
	uint32_t receiveTimestamp;
	uint32_t transmitTimestamp;
	
	/*
	 * used by ppe_parsePacket_icmp4.
	 */
	uint32_t ipAddress[2];
	uint16_t ports[2];
	uint8_t  ipProtoc;
	uint8_t  inputType,inputCode;
	uint8_t  ipHdrLen;
	
	enum ICMPv4_payload payloadType  : 4;
	enum ICMPv4_message messageType  : 4;
	enum ICMPv4_meaning mesgMeaning  : 4;
	enum ICMPv4_IpValidityLevel ipvl : 4;
} ICMPv4_Arguments;


/*
 * @brief creates an ICMPv4 Packet with IP header and 8 follow-on bytes
 * @param  packet  The Packet Buffer.
 * @param  info    Frame Informations
 * @return 0 on success, !=0 otherwise
 * 
 * This function creates an ICMPv4-packet with IP header and 8 follow-on bytes.
 */
int ppe_createDatagramResponse_icmp4(ppeBuffer *packet, ICMPv4_Arguments *args);


/*
 * @brief creates an ICMPv4 Packet with Timestamp
 * @param  packet  The Packet Buffer.
 * @param  info    Frame Informations
 * @return 0 on success, !=0 otherwise
 * 
 * This function creates an ICMPv4-packet with Timestamp.
 */
int ppe_createTimeStamp_icmp4(ppeBuffer *packet, ICMPv4_Arguments *args);


/*
 * @brief creates an ICMPv4 Packet with Address mask
 * @param  packet  The Packet Buffer.
 * @param  info    Frame Informations
 * @return 0 on success, !=0 otherwise
 * 
 * This function creates an ICMPv4-packet with Address mask.
 */
int ppe_createAddressMask_icmp4(ppeBuffer *packet, ICMPv4_Arguments *args);


/*
 * @brief parses an ARP Packet
 * @param  packet  The Packet Buffer.
 * @param  info    Frame Informations
 * @return 0 on success, !=0 otherwise
 * 
 * This function parses an ICMPv4-packet and extracts all header informations.
 */
int ppe_parsePacket_icmp4(ppeBuffer *packet, ICMPv4_Arguments *info);



#endif


