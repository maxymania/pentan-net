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
	uint16_t  sourcePort,destPort;
	uint32_t  seq;
	uint32_t  ack;
	uint8_t   offset;
	uint16_t  flags;
	uint16_t  windowSize;
	uint16_t  checksum;
	uint16_t  urg;
	uint8_t   options[40];
} TCP_SegmentInfo;

/*
 * @brief creates an IPv6 Packet
 * @param  packet  The Packet Buffer.
 * @param  info    Frame Informations
 * @return 0 on success, !=0 otherwise
 * 
 * This function creates an TCP segment with source and destination port.
 */
int ppe_createPacket_tcp(ppeBuffer *packet, TCP_SegmentInfo *info, IPPH_Struct *ipph);

/*
 * @brief parses an IPv6 Packet
 * @param  packet  The Packet Buffer.
 * @param  info    Frame Informations
 * @return 0 on success, !=0 otherwise
 * 
 * This function parses an TCP segment and extracts all header informations.
 */
int ppe_parsePacket_tcp(ppeBuffer *packet, TCP_SegmentInfo *info, IPPH_Struct *ipph);

#endif


