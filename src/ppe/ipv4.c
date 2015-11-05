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

/*
 *             Figure 1: IPv4 packet
 *
 *   0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |Version|  IHL  |   DSCP    |ECN|          Total Length         |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         Identification        |Flags|      Fragment Offset    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  Time to Live |    Protocol   |         Header Checksum       |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                       Source Address                          |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                    Destination Address                        |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *      Additionally/Optionally:
 *
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                          Options                              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     .
 *     .
 *     .
 */

/*
 *    IPv4PacketHeader
 * @brief IPv4-Packet Header
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


/*
 * @brief Calculates the IPv4 header checksum.
 * @param[in] hdr   Pointer to the header.
 * @param[in] ihl2  number of 16-bit words in the header. MUST BE (ihl * 2)!
 *
 * This function calculates the IPv4 checksum for an IPv4 header. It assumes
 * that the ihl2-value is always at least 10 (5 * 2).
 *
 * The algorithm always works correctly without the need for byte-order swapping.
 */
static uint16_t ipHeaderSum(uint16_t* hdr, int ihl2){
	int i;
	register uint32_t check = 0;

	/*
	 * While the checksum is calculated, the checksum field in the header is
	 * temporarily filled up with zero.
	 * 
	 * We implement this by skipping this field in the checksum algorithm.
	 * By doing so, we do not need to set the field to zero in the packet buffer
	 * or to copy the packet header into another buffer for processing.
	 */

	/*
	 * Process the first 5 16-bit words.
	 */
	for(i=0;i<5;++i,++hdr) check+=*hdr;

	/*
	 * Skip the checksum field.
	 */
	++hdr;

	/*
	 * Process the rest of the header.
	 */
	for(i=6;i<ihl2;++i,++hdr) check+=*hdr;

	/*
	 * Folds the result.
	 */
	while(check>>16) check = (check&0xffff)+(check>>16);
	return ~check;
}


int ppe_createPacket_ipv4(ppeBuffer *packet, IPV4_PacketInfo *info) {
	uintptr_t length;int i;
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
	header->totalLength          =  encBE16( (uint16_t) length );
	header->fragmentId           =  encBE16( info->fragmentId );
	header->fragmentOffsetFlags  =  encBE16(
		(info->fragmentOffset&0x1fff)|(info->fragmentFlags<<13)
	);
	header->ttl                  =  info->ttl;
	header->protocol             =  info->protocol;	
	header->srcIPv4Addr          =  info->local;
	header->dstIPv4Addr          =  info->remote;
	for(i=5; i<info->ihl ;++i)
		((Word*)beginHeader)[i].value = encBE32( info->options[i-5] );
	header->checksum             =  ipHeaderSum( beginHeader, info->ihl * 2 );

	/*
	 * Assign the new boundaries to the packet.
	 */
	packet->position   =   beginHeader;
	return 0;
}

int ppe_parsePacket_ipv4(ppeBuffer *packet, IPV4_PacketInfo *info) {
	int ihl,i;
	uint16_t fragment, length;
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
	info->checksum        =  header->checksum;
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

	/*
	 * Copy the IPv4-Options.
	 */
	for(i=5; i<ihl ;++i)
		info->options[i-5] = decBE32( ((Word*)beginHeader)[i].value );

	/*
	 * Perform checksum checking.
	 */
	if( header->checksum != ipHeaderSum( beginHeader, ihl * 2 ) )
		return ERROR_CHECKSUM_MISMATCH;

	/*
	 * Assign the new boundaries to the packet.
	 */
	packet->position   =   endHeader;
	packet->limit      =   endPacket;
	return 0;
}


