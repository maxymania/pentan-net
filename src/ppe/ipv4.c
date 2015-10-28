/*
 * Copyright(C) 2015 Simon Schmidt
 * 
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */
#include <ppe/ipv4.h>
#include <ppe/packing.h>
#include <ppe/stdint.h>
#include <ppe/errornum.h>
#include <ppe/endianess.h>
#include <ppe/_lib_crc.h>


/*
 *    EthernetFrameHeader
 * @brief Ethernet-Frame Header
 */
typedef net_struct_begin{
	/* Word 1 */
	uint8_t versionAndIhl;
	uint8_t dscpAndEcn;
	uint16_t totalLength;

	/* Word 2 */
	uint16_t fragmentId;
	uint16_t fragmentOffsetFlags;

	/* Word 3*/
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;

	uint32_t srcIPv4Addr;
	uint32_t dstIPv4Addr;
} net_struct_end IPv4PacketHeader;


typedef net_struct_begin{
	uint32_t value;
} net_struct_end Word;

typedef void* Pointer;

static uint16_t ipchecksum(uint8_t* pkg, uintptr_t len){
	register uint32_t check = 0;
	while(len>1){
		check+=((uint16_t)pkg[1])|(((uint16_t)pkg[0])<<8);
		len-=2;
		pkg+=2;
	}
	if(len>0) check += pkg[0];
	while(check>>16) check = (check&0xffff)+(check>>16);
	return check;
}

int ppe_createPacket_ipv4(ppeBuffer *packet, IPV4_FrameInfo *info) {
	uintptr_t length;
	Pointer beginHeader, endHeader,endPacket;
	IPv4PacketHeader *header;

	/*
	 * Check the IHL boundaries.
	 */
	if( info->ihl<5 || info->ihl >15 ) return ERROR_BUFFER_OVERFLOW;

	/*
	 * Calculate the Packet header size
	 */
	endHeader    = packet->position;
	endPacket    = packet->limit;
	beginHeader  = endHeader-(4*info->ihl);

	/*
	 * Bound-check the Header.
	 */
	if( beginHeader < packet->begin) return ERROR_BUFFER_OVERFLOW;

	/*
	 * Check the packet length.
	 */
	length = endPacket-beginHeader;
	if( length > 0xffff ) return ERROR_BUFFER_OVERFLOW;

	/*
	 * Fill the packet header.
	 */
	header                       =  beginHeader;
	header->versionAndIhl        =  0x40 | info->ihl;
	header->dscpAndEcn           =  encBE16( info->dscpAndEcn );
	header->totalLength          =  length;
	header->fragmentId           =  encBE16( info->fragmentId );
	header->fragmentOffsetFlags  =  encBE16(
		(info->fragmentOffset&0x1fff)|(info->fragmentFlags<<13)
	);
	header->ttl                  =  info->ttl;
	header->protocol             =  info->protocol;
	header->checksum             =  encBE16(
				ipchecksum(beginHeader,endHeader-beginHeader) );
	header->srcIPv4Addr          =  info->local;
	header->dstIPv4Addr          =  info->remote;

	/*
	 * Assign the new boundaries to the packet.
	 */
	packet->position   =   beginHeader;
	return 0;
}

int ppe_parsePacket_ipv4(ppeBuffer *packet, IPV4_FrameInfo *info) {
	int ihl, length,i; uint16_t fragment;
	Pointer beginHeader, endHeader,endPacket;
	IPv4PacketHeader *header;
	
	/*
	 * Preliminary Header boundaries
	 */
	beginHeader  =  packet->position;
	endHeader    =  beginHeader + sizeof(IPv4PacketHeader);

	/*
	 * Bounds-check header.
	 */
	if( endHeader > packet->limit ) return ERROR_BUFFER_OVERFLOW;

	header  =  beginHeader;

	/*
	 * Check Version field
	 */
	if( (header->versionAndIhl&0xf0) != 0x40 ) return ERROR_PROTOCOL_VIOLATION;

	/*
	 * Extract every header field.
	 */
	ihl = info->ihl       =  (header->versionAndIhl&0xf);
	info->dscpAndEcn      =  decBE16( header->dscpAndEcn );
	length = info->length =  decBE16( header->totalLength );
	info->fragmentId      =  decBE16( header->fragmentId );
	fragment              =  decBE16( header->fragmentOffsetFlags );
	info->fragmentFlags   =  fragment >> 13;
	info->fragmentOffset  =  fragment & 0x1fff;
	info->ttl             =  header->ttl;
	info->protocol        =  header->protocol;
	info->checksum        =  decBE16( header->checksum );
	info->remote          =  header->srcIPv4Addr;
	info->local           =  header->dstIPv4Addr;


	/*
	 * Calculate the end of the packet.
	 * Recalculate the end of the header.
	 */
	endPacket = beginHeader + length;
	endHeader = beginHeader+(4*ihl);

	/*
	 * Perform Bounds checking.
	 */
	if( endPacket > packet->limit ) return ERROR_BUFFER_OVERFLOW;
	if( (beginHeader+(4*ihl)) > endPacket ) return ERROR_BUFFER_OVERFLOW;
	if( ihl<5 || ihl>15 ) return ERROR_BUFFER_OVERFLOW;
	for(i=5; i<ihl ;++i)
		info->options[i-5] = ((Word*)beginHeader)[i].value;

	if( info->checksum != ipchecksum(beginHeader,endHeader-beginHeader) )
		return ERROR_CHECKSUM_MISMATCH;

	/*
	 * Assign the new boundaries to the packet.
	 */
	packet->position   =   endHeader;
	packet->limit      =   endPacket;
	return 0;
}


