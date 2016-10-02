/*
 * Copyright(C) 2016 Simon Schmidt
 * 
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */
#ifndef PPE_ARP_H
#define PPE_ARP_H
#include <ppe/stdint.h>
#include <ppe/buffer.h>
#include <ppe/ipv4.h>
#include <ppe/ethernet.h>


typedef struct{
	MacAddress  hardAddress[2];
	IPv4Address protAddress[2];

	uint16_t opCode;

	/* defines the order of the address pair for createPacket
	 * 0 = {source,dest}
	 * 1 = {dest,source}
	 * parsePacket will set it to 0.
	 */
	unsigned sourcePos : 1;
} ARP_PacketInfo;

/*
 * @brief creates an ARP Packet
 * @param  packet  The Packet Buffer.
 * @param  info    Frame Informations
 * @return 0 on success, !=0 otherwise
 * 
 * This function creates an ARP packet with source and destination address.
 */
int ppe_createPacket_arp(ppeBuffer *packet, ARP_PacketInfo *info);

/*
 * @brief parses an ARP Packet
 * @param  packet  The Packet Buffer.
 * @param  info    Frame Informations
 * @return 0 on success, !=0 otherwise
 * 
 * This function parses an ARP packet and extracts all header informations.
 */
int ppe_parsePacket_arp(ppeBuffer *packet, ARP_PacketInfo *info);

#endif


