/*
 * Copyright(C) 2015 Simon Schmidt
 * 
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */
#include <ppe/ethernet.h>
#include <ppe/packing.h>
#include <ppe/stdint.h>
#include <ppe/errornum.h>
#include <ppe/tcp.h>
#include <ppe/endianess.h>

/*
 *    TcpSegmentHeader
 * @brief TCP-Segment Header
 */
typedef net_struct_begin{
	uint16_t sourcePort;
	uint16_t destPort;
	uint32_t seq;
	uint32_t ack;
	uint16_t dataOffsetFlags;
	uint16_t windowSize;
	uint16_t checksum;
	uint16_t urg;
} net_struct_end TcpSegmentHeader;

typedef void* Pointer;

static uint16_t tcpHeaderSum(uint16_t* content, uintptr_t size, IPPH_Struct *ipph){
	int i;
	uint64_t check = 0;

	check = ppe_ipphChecksum(ipph, size);

	/*
	 * Process the first 8 16-bit words.
	 */
	for(i=0;i<8;++i,++content,size-=2) check+=*content;

	/*
	 * Skip the checksum field.
	 */
	++content;

	/*
	 * Process the rest of the header.
	 */
	while(size>1) {
		check+=*content;
		++content;
		size-=2;
	}

	if(size){
		check += *((uint8_t*)content);
	}

	/*
	 * Folds the result.
	 */
	while(check>>16) check = (check&0xffff)+(check>>16);
	return ~check;
}

static void copy(uint8_t *src,uint8_t *dst, int num){
	int i;
	for(i=0;i<num;++i)
		dst[i] = src[i];
}

int ppe_createPacket_tcp(ppeBuffer *packet, TCP_SegmentInfo *info, IPPH_Struct *ipph) {

	// TODO: Implement
	return 1;
}


// TODO: comments!
int ppe_parsePacket_tcp(ppeBuffer *packet, TCP_SegmentInfo *info, IPPH_Struct *ipph) {
	uint16_t dataOffsetFlags;
	Pointer beginHeader,endHeader,endPacket;
	TcpSegmentHeader *header;

	beginHeader = packet->position;
	endPacket = packet->limit;

	endHeader = beginHeader + sizeof(TcpSegmentHeader);
	if( endHeader > endPacket ) return ERROR_BUFFER_OVERFLOW;

	header            =   beginHeader;
	info->sourcePort  =   decBE16( header->sourcePort );
	info->destPort    =   decBE16( header->destPort );
	info->seq         =   decBE32( header->seq );
	info->ack         =   decBE32( header->ack );
	dataOffsetFlags   =   decBE16( header->dataOffsetFlags );
	info->offset      =   dataOffsetFlags >> 12;
	info->flags       =   dataOffsetFlags & 0x1ff;
	info->windowSize  =   decBE16( header->windowSize );
	info->checksum    =   header->checksum;
	info->urg         =   decBE16( header->urg );

	if( info->offset < 5 ) return ERROR_BUFFER_OVERFLOW;
	endHeader = beginHeader + ( info->offset * 4 );
	if( endHeader > endPacket ) return ERROR_BUFFER_OVERFLOW;

	copy(
		beginHeader + sizeof(TcpSegmentHeader),
		info->options,
		(info->offset-5) * 4
	);

	
	if( info->checksum != tcpHeaderSum( beginHeader, endPacket-beginHeader, ipph) )
		return ERROR_CHECKSUM_MISMATCH;

	/*
	 * Assign the new boundaries to the packet.
	 */
	packet->position   =   endHeader;
	return 1;
}


