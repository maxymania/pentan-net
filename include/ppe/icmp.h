/*
 * Copyright(C) 2016 Simon Schmidt
 * 
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */
#ifndef PPE_ICMP_H
#define PPE_ICMP_H
#include <ppe/stdint.h>
#include <ppe/buffer.h>
#include <ppe/ethernet.h>
#include <ppe/phlite.h>

typedef struct{
	uint8_t type,code;
	uint16_t checksum;
	IPPH_Info phCheckSum;
} ICMP_PacketInfo;

/*
 * @brief creates an ICMP Packet
 * @param  packet  The Packet Buffer.
 * @param  info    Frame Informations
 * @return 0 on success, !=0 otherwise
 * 
 * This function creates an ICMP-packet with source and destination address.
 */
int ppe_createPacket_icmp(ppeBuffer *packet, ICMP_PacketInfo *info);

/*
 * @brief parses an ICMP Packet
 * @param  packet  The Packet Buffer.
 * @param  info    Frame Informations
 * @return 0 on success, !=0 otherwise
 * 
 * This function parses an ICMP-packet and extracts all header informations.
 */
int ppe_parsePacket_icmp(ppeBuffer *packet, ICMP_PacketInfo *info);

#endif


