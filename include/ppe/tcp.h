/*
 * Copyright(C) 2015-2016 Simon Schmidt
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
#include <ppe/phlite.h>

typedef struct{
	/*
	 * Ports as defined in the field 'sourcePos'.
	 * Note that ports are stored in network byte order.
	 */
	uint16_t  ports[2];
	uint32_t  seq;
	uint32_t  ack;
	uint8_t   offset;
	uint16_t  flags;
	uint16_t  windowSize;
	uint16_t  checksum;
	uint16_t  urg;
	uint8_t   options[40];

	IPPH_Info phCheckSum;

	/* defines the order of the port pair for createPacket
	 * 0 = {source,dest}
	 * 1 = {dest,source}
	 * parsePacket will set it to 0.
	 */
	unsigned sourcePos : 1;
} TCP_SegmentInfo;

enum {
	TCPF_FIN = 0x001,
	TCPF_SYN = 0x002,
	TCPF_RST = 0x004,
	TCPF_PSH = 0x008,
	TCPF_ACK = 0x010,
	TCPF_URG = 0x020,
	TCPF_ECE = 0x040,
	TCPF_CWR = 0x080,
	TCPF_NS  = 0x100,
};

/*
 * @brief creates an TCP segment
 * @param  packet  The Packet Buffer.
 * @param  info    Frame Informations
 * @return 0 on success, !=0 otherwise
 * 
 * This function creates an TCP segment with source and destination port.
 */
int ppe_createPacket_tcp(ppeBuffer *packet, TCP_SegmentInfo *info);

/*
 * @brief parses an TCP segment
 * @param  packet  The Packet Buffer.
 * @param  info    Frame Informations
 * @return 0 on success, !=0 otherwise
 * 
 * This function parses an TCP segment and extracts all header informations.
 */
int ppe_parsePacket_tcp(ppeBuffer *packet, TCP_SegmentInfo *info);

#endif


