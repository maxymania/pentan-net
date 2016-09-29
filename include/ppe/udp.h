/*
 * Copyright(C) 2015-2016 Simon Schmidt
 * 
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */
#ifndef PPE_UDP_H
#define PPE_UDP_H
#include <ppe/stdint.h>
#include <ppe/buffer.h>
#include <ppe/phlite.h>

typedef struct{
	/*
	 * Ports as defined in the field 'sourcePos'.
	 * Note that ports are stored in network byte order.
	 */
	uint16_t  ports[2];
	uint16_t  length;
	uint16_t  checksum;

	IPPH_Info phCheckSum;

	/* defines the order of the port pair for createPacket
	 * 0 = {source,dest}
	 * 1 = {dest,source}
	 * parsePacket will set it to 0.
	 */
	unsigned sourcePos : 1;
} UDP_PacketInfo;

/*
 * @brief creates an UDP packet
 * @param  packet  The Packet Buffer.
 * @param  info    Frame Informations
 * @return 0 on success, !=0 otherwise
 * 
 * This function creates an UDP packet with source and destination port.
 */
int ppe_createPacket_udp(ppeBuffer *packet, UDP_PacketInfo *info);

/*
 * @brief parses an UDP packet
 * @param  packet  The Packet Buffer.
 * @param  info    Frame Informations
 * @return 0 on success, !=0 otherwise
 * 
 * This function parses an UDP packet and extracts all header informations.
 */
int ppe_parsePacket_udp(ppeBuffer *packet, UDP_PacketInfo *info);

#endif


