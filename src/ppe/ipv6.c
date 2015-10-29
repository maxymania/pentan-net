/*
 * Copyright(C) 2015 Simon Schmidt
 * 
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */
#include <ppe/ipv6.h>
#include <ppe/packing.h>
#include <ppe/stdint.h>
#include <ppe/errornum.h>
#include <ppe/endianess.h>


/*
 *    IPv6PacketHeader
 * @brief Ethernet-Frame Header
 */
typedef net_struct_begin{
	/*
	 * version | Traffic Class | Flow Label
	 */
	uint32_t verTcFlowLabel;
	uint16_t payloadLength;
	uint8_t nextHeader;
	uint8_t hopLimit;
	uint8_t srcIPv6Addr[16];
	uint8_t dstIPv6Addr[16];
} net_struct_end IPv6PacketHeader;

/*
 *    IPv6Addr
 * @brief IPv6 Address
 * This structure is designed, to efficiently assign a mac address.
 */
typedef net_struct_begin{
	uint8_t content[16];
} net_struct_end IPv6Addr;

typedef void* Pointer;

int ppe_createPacket_ipv6(ppeBuffer *packet, IPV6_PacketInfo *info) {
	uint32_t verTcFlowLabel;uintptr_t length;
	Pointer beginHeader, endHeader, endPacket;
	IPv6PacketHeader *header;

	/*
	 * Unpack memory address of the start and end of the packet.
	 */
	endHeader    =   packet->position;
	endPacket    =   packet->limit;

	/*
	 * Calculating the outer packet boundaries.
	 */
	beginHeader  =   endHeader - sizeof(IPv6PacketHeader);

	/*
	 * Check the packet length.
	 */
	length = endPacket-endHeader;
	if( length > 0xffff ) return ERROR_BUFFER_OVERFLOW;

	/*
	 * Check, wether the new frame exceeds the buffer boundaries.
	 */
	if(beginHeader < packet->begin) return ERROR_BUFFER_OVERFLOW;

	/*
	 * Assign the header and footer struct-pointers.
	 */
	header  =  beginHeader;

	/*
	 * Construct the header.
	 */
	verTcFlowLabel                     =   (6<<28) |
                                           (info->trafficClass<<20) |
                                           (info->flowLabel & 0xfffff);
	header->verTcFlowLabel             =   encBE32( verTcFlowLabel );
	header->payloadLength              =   encBE16( (uint16_t) length );
	header->nextHeader                 =   info->protocol;
	header->hopLimit                   =   info->ttl;
	*((IPv6Addr*)header->srcIPv6Addr)  =   *((IPv6Addr*)info->local);
	*((IPv6Addr*)header->dstIPv6Addr)  =   *((IPv6Addr*)info->remote);

	/*
	 * Assign the new boundaries to the packet.
	 */
	packet->position  =  beginHeader;
	return 0;
}

int ppe_parsePacket_ipv6(ppeBuffer *packet, IPV6_PacketInfo *info) {
	uint32_t verTcFlowLabel;
	uint16_t length;
	Pointer beginHeader, endHeader, endPacket;
	IPv6PacketHeader *header;

	/*
	 * Preliminary Header boundaries
	 */
	beginHeader  =  packet->position;
	endHeader    =  beginHeader + sizeof(IPv6PacketHeader);

	/*
	 * Bounds-check header.
	 */
	if( endHeader > packet->limit ) return ERROR_BUFFER_OVERFLOW;

	/*
	 * Extract all necessary informations from the header to perform sanity,
	 * conformance and bounds checks.
	 */
	header                =  beginHeader;
	verTcFlowLabel        =  decBE32( header->verTcFlowLabel );
	length                =  decBE16( header->payloadLength );

	/*
	 * Check the Version field.
	 */
	if( (verTcFlowLabel>>28) != 6 ) return ERROR_PROTOCOL_VIOLATION;

	/*
	 * Bounds-check the packet size.
	 */
	endPacket = endHeader + length;
	if( endPacket > packet->limit ) return ERROR_BUFFER_OVERFLOW;

	/*
	 * Extract all informations from the packet header.
	 */
	info->flowLabel             =   (verTcFlowLabel & 0xfffff);
	info->trafficClass          =   ((verTcFlowLabel>>20) & 0xff);
	info->length                =   length;
	info->protocol              =   header->nextHeader;
	info->ttl                   =   header->hopLimit;
	*((IPv6Addr*)info->remote)  =   *((IPv6Addr*)header->srcIPv6Addr);
	*((IPv6Addr*)info->local)   =   *((IPv6Addr*)header->dstIPv6Addr);

	/*
	 * Assign the new boundaries to the packet.
	 */
	packet->position   =   endHeader;
	packet->limit      =   endPacket;
	return 0;
}


