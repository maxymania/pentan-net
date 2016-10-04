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
#include <ppe/udp.h>
#include <ppe/endianess.h>
#include <ppe/ip.h>

/*
 *    UdpPacketHeader
 * @brief UDP-Packet Header
 */
typedef net_struct_begin{
	uint16_t sourcePort;
	uint16_t destPort;
	uint16_t length;
	uint16_t checksum;
} net_struct_end UdpPacketHeader;

typedef void* Pointer;

static inline uint16_t udpChecksum(uint16_t* content, uintptr_t size, UDP_PacketInfo *info){
	int i = 0;
	uint32_t check = 0;

	check  = info->phCheckSum.headerCheckSum;
	check += encBE16(size&0xFFFF);
	check += encBE16(IPProto_UDP);
	if(info->phCheckSum.modeIsV6) check += encBE16((size>>16)&0xFFFF);

	/*
	 * Process the udp-header, except the checksum-field.
	 */
	check   += content[0];
	check   += content[1];
	check   += content[2];
	size    -= 8;
	content += 4;

	/*
	 * Process the rest of the packet.
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

int ppe_createPacket_udp(ppeBuffer *packet, UDP_PacketInfo *info) {
	uint16_t length;
	Pointer beginHeader,endHeader,endPacket;
	UdpPacketHeader *header;

	/*
	 * Calculate the Packet header size.
	 */
	endHeader    = packet->position;
	endPacket    = packet->limit;
	beginHeader  = endHeader-sizeof(UdpPacketHeader);

	if( (endPacket-beginHeader) > 0xffff) {
		/*
		 * In IPv6 jumbograms it's possible to have UDP packets of size
		 * greater than 65535 bytes. (see RFC2675)
		 *
		 * Then, the length field must be set to zero.
		 */
		if(info->phCheckSum.modeIsV6) return ERROR_BUFFER_OVERFLOW;
		length = 0;
	}else{
		length = (endPacket-beginHeader);
	}

	/*
	 * Bound-check the Header.
	 */
	if( beginHeader < packet->begin) return ERROR_BUFFER_OVERFLOW;

	/*
	 * Build the UDP header
	 */
	header                   =  beginHeader;
	header->sourcePort       =  info->ports[info->sourcePos  ];
	header->destPort         =  info->ports[info->sourcePos^1];
	header->length           =  encBE16( info->length );

	/*
	 * Calculate the UDP Checksum.
	 */
	header->checksum   =  udpChecksum( beginHeader, endPacket-beginHeader, info);

	/*
	 * Assign the new boundaries to the packet.
	 */
	packet->position   =   beginHeader;
	return 0;
}

int ppe_parsePacket_udp(ppeBuffer *packet, UDP_PacketInfo *info) {
	uint16_t dataOffsetFlags;
	Pointer beginHeader,endHeader,endPacket;
	UdpPacketHeader *header;

	/*
	 * Get the begin-pointer, and the end-pointer of the packet.
	 */
	beginHeader = packet->position;
	endPacket = packet->limit;

	/*
	 * Calculate the preliminary header boundaries, and perform bounds-checks.
	 */
	endHeader = beginHeader + sizeof(UdpPacketHeader);
	if( endHeader > endPacket ) return ERROR_BUFFER_OVERFLOW;

	/*
	 * Unpack the UDP-Header.
	 */
	header            =   beginHeader;
	info->sourcePos   =   0;
	info->ports[0]    =   header->sourcePort;
	info->ports[1]    =   header->destPort;
	info->length      =   decBE16( header->length );
	info->checksum    =   header->checksum;

	/*
	 * Handle the length-field of the UDP-Header.
	 *
	 *
	 * In IPv6 jumbograms it's possible to have UDP packets of size
	 * greater than 65535 bytes. (see RFC2675)
	 *
	 * Then, the length field must be set to zero.
	 *
	 * However, from time to time, those packets are also crafted from
	 * RFC incompliant Networking Stacks, so we tolerate this as even
	 * if a zero-length would be forbidden otherwise. (ROBUSTNESS)
	 *
	 */
	if( info->length ) {
		if( info->length < 8 ) return ERROR_BUFFER_OVERFLOW;
		endPacket = beginHeader+info->length;
		if( endPacket > packet->limit ) return ERROR_BUFFER_OVERFLOW;
	}

	/*
	 * Perform checksum checking.
	 */
	if( info->checksum != udpChecksum( beginHeader, endPacket-beginHeader, info) )
		return ERROR_CHECKSUM_MISMATCH;

	/*
	 * Assign the new boundaries to the packet.
	 */
	packet->position   =   endHeader;
	return 0;
}


