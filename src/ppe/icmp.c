/*
 * Copyright(C) 2015-2016 Simon Schmidt
 * 
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */
#include <ppe/icmp.h>
#include <ppe/packing.h>
#include <ppe/stdint.h>
#include <ppe/errornum.h>
#include <ppe/endianess.h>

/*
 *    The first 4 bytes of the ICMP-Header. The next 4 bytes are concidered 
 * @brief ARP-Packet Header
 */
typedef net_struct_begin{
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
} net_struct_end IcmpPacketHeader;

typedef void* Pointer;

static inline uint16_t icmpChecksum(uint16_t* content, uintptr_t size, ICMP_PacketInfo *info){
	int i = 0;
	uint32_t check = 0;

	check  = info->phCheckSum.headerCheckSum;
	check += encBE16(size&0xFFFF);
	if(info->phCheckSum.modeIsV6) check += encBE16((size>>16)&0xFFFF);


	/*
	 * Process the first 16-bit word.
	 */
	check+=*content;

	/*
	 * Skip the checksum field.
	 */
	content+=2;
	size-=4;
	

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

int ppe_createPacket_icmp(ppeBuffer *packet, ICMP_PacketInfo *info){
	Pointer beginHeader, endHeader, endPacket;
	IcmpPacketHeader *header;

	/*
	 * Unpack memory address of the start and end of the packet.
	 */
	endHeader    =   packet->position;
	endPacket    =   packet->limit;

	/*
	 * Calculating the outer packet boundaries.
	 */
	beginHeader  =   endHeader - sizeof(IcmpPacketHeader);

	/*
	 * Check, wether the new frame exceeds the buffer boundaries.
	 */
	if(beginHeader < packet->begin) return ERROR_BUFFER_OVERFLOW;

	/*
	 * Construct the header.
	 */
	header       = beginHeader;
	header->type = info->type;
	header->code = info->code;

	/*
	 * Calculate the TCP Checksum.
	 */
	header->checksum   =  icmpChecksum( beginHeader, endPacket-beginHeader, info);

	return 0;
}


int ppe_parsePacket_icmp(ppeBuffer *packet, ICMP_PacketInfo *info){
	Pointer beginHeader, endHeader, endPacket;
	IcmpPacketHeader *header;

	/*
	 * Unpack memory address of the start and end of the packet.
	 */
	beginHeader    =   packet->position;
	endPacket      =   packet->limit;

	/*
	 * Bounds-check header.
	 */
	endHeader      =   beginHeader + sizeof(IcmpPacketHeader);
	if( endHeader > endPacket ) return ERROR_BUFFER_OVERFLOW;

	/*
	 * Extract all informations from the packet header.
	 */
	info->type     = header->type;
	info->code     = header->code;
	info->checksum = header->checksum;

	/*
	 * Perform checksum checking.
	 */
	if( info->checksum != icmpChecksum( beginHeader, endPacket-beginHeader, info) )
		return ERROR_CHECKSUM_MISMATCH;

	/*
	 * Assign the new boundaries to the packet.
	 */
	packet->position = endHeader;
	return 0;
}

