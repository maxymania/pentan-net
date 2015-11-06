/*
 * Copyright(C) 2015 Simon Schmidt
 * 
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */
#ifndef PPE_TCP_H
#define PPE_TCP_H
#include <ppe/stdint.h>
#include <ppe/buffer.h>
#include <ppe/ip_ph.h>

typedef struct{
	uint16_t  remotePort,localPort;
	uint16_t  length;
	uint16_t  checksum;
} UDP_PacketInfo;

/*
 * @brief creates an UDP packet
 * @param  packet  The Packet Buffer.
 * @param  info    Frame Informations
 * @return 0 on success, !=0 otherwise
 * 
 * This function creates an UDP packet with source and destination port.
 */
int ppe_createPacket_udp(ppeBuffer *packet, UDP_PacketInfo *info, IPPH_Struct *ipph);

/*
 * @brief parses an UDP packet
 * @param  packet  The Packet Buffer.
 * @param  info    Frame Informations
 * @return 0 on success, !=0 otherwise
 * 
 * This function parses an UDP packet and extracts all header informations.
 */
int ppe_parsePacket_udp(ppeBuffer *packet, UDP_PacketInfo *info, IPPH_Struct *ipph);

#endif


