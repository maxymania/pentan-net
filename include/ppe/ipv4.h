/*
 * Copyright(C) 2015-2016 Simon Schmidt
 * 
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */
#ifndef PPE_IPV4_H
#define PPE_IPV4_H
#include <ppe/stdint.h>
#include <ppe/buffer.h>


typedef uint32_t IPv4Address;

typedef struct{
	IPv4Address address[2];
	uint8_t ihl; /* must be at least 5 and at most 15 */
	uint16_t fragmentId;
	uint8_t fragmentFlags;
	uint16_t fragmentOffset;
	
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	uint16_t dscpAndEcn;
	
	 /* ignored in createPacket */
	uint16_t length;
	uint32_t options[10];

	/* defines the order of the address pair for createPacket
	 * 0 = {source,dest}
	 * 1 = {dest,source}
	 * parsePacket will set it to 0.
	 */
	unsigned sourcePos : 1;
} IPV4_PacketInfo;

enum {
	IPV4_FRAG_DF = 2,
	IPV4_FRAG_MF = 1,
};

/*
 * @brief creates an IPv4 Packet
 * @param  packet  The Packet Buffer.
 * @param  info    Frame Informations
 * @return 0 on success, !=0 otherwise
 * 
 * This function creates an IPv4 packet with source and destination address.
 */
int ppe_createPacket_ipv4(ppeBuffer *packet, IPV4_PacketInfo *info);

/*
 * @brief parses an IPv4 Packet
 * @param  packet  The Packet Buffer.
 * @param  info    Frame Informations
 * @return 0 on success, !=0 otherwise
 * 
 * This function parses an IPv4 packet and extracts all header informations.
 */
int ppe_parsePacket_ipv4(ppeBuffer *packet, IPV4_PacketInfo *info);

#endif


