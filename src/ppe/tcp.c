/*
 * Copyright(C) 2015-2016 Simon Schmidt
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
//#include <ppe/_lib_tcpsum.h>

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

static inline uint16_t tcpChecksum(uint16_t* content, uintptr_t size, TCP_SegmentInfo *info){
	int i = 0;
	uint32_t check = 0;

	check  = info->phCheckSum.headerCheckSum;
	check += encBE16(size&0xFFFF);
	if(info->phCheckSum.modeIsV6) check += encBE16((size>>16)&0xFFFF);


	/*
	 * Process the first 8 16-bit words.
	 */
	for(i=0;i<8;++i,++content,size-=2) check+=*content;

	/*
	 * Skip the checksum field.
	 */
	++content;
	size-=2;

	/*
	 * Process the rest of the segment.
	 */
	while(size>1) {
		check+=*content;
		++content;
		size-=2;

		/*
		 * Prevent the check integer from overflowing.
		 */
		if(++i>0xfff0){
			check = (check&0xffff)+(check>>16);
			check = (check&0xffff)+(check>>16);
			i=0;
		}
	}

	if(size){
		check += *((uint8_t*)content);
	}

	/*
	 * Folds the result.
	 */
	check = (check&0xffff)+(check>>16);
	check = (check&0xffff)+(check>>16);
	return ~check;
}

static inline void copy(uint8_t *src,uint8_t *dst, int num){
	int i;
	for(i=0;i<num;++i)
		dst[i] = src[i];
}

int ppe_createPacket_tcp(ppeBuffer *packet, TCP_SegmentInfo *info) {
	uint16_t dataOffsetFlags;
	Pointer beginHeader,endHeader,endPacket;
	TcpSegmentHeader *header;

	/*
	 * Check the Offset boundaries.
	 */
	if( info->offset<5 || info->offset >15 ) return ERROR_BUFFER_OVERFLOW;

	/*
	 * Calculate the Packet header size.
	 */
	endHeader    = packet->position;
	endPacket    = packet->limit;
	beginHeader  = endHeader-(4*info->offset);

	/*
	 * Bound-check the Header.
	 */
	if( beginHeader < packet->begin) return ERROR_BUFFER_OVERFLOW;

	/*
	 * Build the TCP header
	 */
	header                   =  beginHeader;
	header->sourcePort       =  info->ports[info->sourcePos  ];
	header->destPort         =  info->ports[info->sourcePos^1];
	header->seq              =  encBE32( info->seq );
	header->ack              =  encBE32( info->ack );
	dataOffsetFlags          =  ((info->offset)<<12)|info->flags;
	header->dataOffsetFlags  =  encBE16( dataOffsetFlags);
	header->windowSize       =  encBE16( info->windowSize );
	header->urg              =  encBE16( info->urg );

	/*
	 * Copy the TCP-Options.
	 */
	copy(
		info->options,
		beginHeader + sizeof(TcpSegmentHeader),
		(info->offset-5) * 4
	);

	/*
	 * Calculate the TCP Checksum.
	 */
	header->checksum   =  tcpChecksum( beginHeader, endPacket-beginHeader, info);

	/*
	 * Assign the new boundaries to the packet.
	 */
	packet->position   =   beginHeader;
	return 0;
}


int ppe_parsePacket_tcp(ppeBuffer *packet, TCP_SegmentInfo *info) {
	uint16_t dataOffsetFlags;
	Pointer beginHeader,endHeader,endPacket;
	TcpSegmentHeader *header;

	/*
	 * Get the begin-pointer, and the end-pointer of the packet.
	 */
	beginHeader = packet->position;
	endPacket = packet->limit;

	/*
	 * Calculate the preliminary header boundaries, and perform bounds-checks.
	 */
	endHeader = beginHeader + sizeof(TcpSegmentHeader);
	if( endHeader > endPacket ) return ERROR_BUFFER_OVERFLOW;

	/*
	 * Unpack the TCP-Header.
	 */
	header            =   beginHeader;
	info->sourcePos   =   0;
	info->ports[0]    =   header->sourcePort;
	info->ports[1]    =   header->destPort;
	info->seq         =   decBE32( header->seq );
	info->ack         =   decBE32( header->ack );
	dataOffsetFlags   =   decBE16( header->dataOffsetFlags );
	info->offset      =   dataOffsetFlags >> 12;
	info->flags       =   dataOffsetFlags & 0x1ff;
	info->windowSize  =   decBE16( header->windowSize );
	info->checksum    =   header->checksum;
	info->urg         =   decBE16( header->urg );

	/*
	 * Recalculate the end of the header, and perform bounds-checks.
	 */
	if( info->offset < 5 ) return ERROR_BUFFER_OVERFLOW;
	endHeader = beginHeader + ( info->offset * 4 );
	if( endHeader > endPacket ) return ERROR_BUFFER_OVERFLOW;

	/*
	 * Copy the TCP-Options.
	 */
	copy(
		beginHeader + sizeof(TcpSegmentHeader),
		info->options,
		(info->offset-5) * 4
	);

	/*
	 * Perform checksum checking.
	 */
	if( info->checksum != tcpChecksum( beginHeader, endPacket-beginHeader, info) )
		return ERROR_CHECKSUM_MISMATCH;

	/*
	 * Assign the new boundaries to the packet.
	 */
	packet->position   =   endHeader;
	return 0;
}


