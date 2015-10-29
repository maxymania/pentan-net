/*
 * Copyright(C) 2015 Simon Schmidt
 * 
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */
#ifndef PPE_IPV6_H
#define PPE_IPV6_H
#include <ppe/stdint.h>
#include <ppe/buffer.h>


typedef uint8_t IPv6Address[16];

typedef struct{
	IPv6Address remote,local;
	uint32_t flowLabel;
	uint8_t trafficClass;
	union {
		uint8_t ttl;
		uint8_t hopLimit;
	};
	union {
		uint8_t protocol;
		uint8_t nextHeader;
	};

	 /* ignored in createPacket */
	uint16_t length;
} IPV6_PacketInfo;

/*
 * @brief creates an IPv6 Packet
 * @param  packet  The Packet Buffer.
 * @param  info    Frame Informations
 * @return 0 on success, !=0 otherwise
 * 
 * This function creates an IPv6 packet with source and destination address.
 */
int ppe_createPacket_ipv6(ppeBuffer *packet, IPV6_PacketInfo *info);

/*
 * @brief parses an IPv6 Packet
 * @param  packet  The Packet Buffer.
 * @param  info    Frame Informations
 * @return 0 on success, !=0 otherwise
 * 
 * This function parses an IPv6 packet and extracts all header informations.
 */
int ppe_parsePacket_ipv6(ppeBuffer *packet, IPV6_PacketInfo *info);

#endif


