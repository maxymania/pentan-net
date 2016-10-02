/*
 * Copyright(C) 2016 Simon Schmidt
 * 
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */
#include <ppe/arp.h>
#include <ppe/packing.h>
#include <ppe/stdint.h>
#include <ppe/errornum.h>
#include <ppe/endianess.h>

/*
 *    ArpPacketHeader
 * @brief ARP-Packet Header
 */
typedef net_struct_begin{
	uint16_t hardAddrType; /* =1 for ethernet. */
	
	uint16_t protAddrType; /* =0x0800 for IPv4. */
	
	uint8_t  hardAddrSize; /* =6 for ethernet. */
	uint8_t  protAddrSize; /* =4 for IPv4 */
	
	uint16_t opCode;
	
	MacAddress  hardAddrSource;
	IPv4Address protAddrSource;
	MacAddress  hardAddrTarget;
	IPv4Address protAddrTarget;
} net_struct_end ArpPacketHeader;

/*
 *    MacAddr
 * @brief Mac Address
 * This structure is designed, to efficiently assign a mac address.
 */
typedef net_struct_begin{
	uint8_t content[6];
} net_struct_end MacAddr;

typedef void* Pointer;

int ppe_createPacket_arp(ppeBuffer *packet, ARP_PacketInfo *info) {
	Pointer beginHeader, endHeader, endPacket;
	ArpPacketHeader *header;

	/*
	 * Unpack memory address of the start and end of the packet.
	 */
	endHeader    =   packet->position;
	endPacket    =   packet->limit;

	/*
	 * Calculating the outer packet boundaries.
	 */
	beginHeader  =   endHeader - sizeof(ArpPacketHeader);

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
	header->hardAddrType                =  encBE16(1);
	header->protAddrType                =  encBE16(0x0800);
	header->hardAddrSize                =  6;
	header->protAddrSize                =  4;
	header->opCode                      =  encBE16(info->opCode);
	*((MacAddr*)header->hardAddrSource) =  *((MacAddr*)info->hardAddress[info->sourcePos  ]);
	header->protAddrSource              =  info->protAddress[info->sourcePos  ];
	*((MacAddr*)header->hardAddrTarget) =  *((MacAddr*)info->hardAddress[info->sourcePos^1]);
	header->protAddrTarget              =  info->protAddress[info->sourcePos^1];

	/*
	 * Assign the new boundaries to the packet.
	 */
	packet->position  =  beginHeader;
	return 0;
}

int ppe_parsePacket_arp(ppeBuffer *packet, ARP_PacketInfo *info) {
	uint16_t hardType,protType;
	uint8_t hardSize,protSize;
	Pointer beginHeader, endHeader, endPacket;
	ArpPacketHeader *header;

	/*
	 * Preliminary Header boundaries
	 */
	beginHeader  =  packet->position;
	endHeader    =  beginHeader + sizeof(ArpPacketHeader);

	/*
	 * Bounds-check header.
	 */
	if( endHeader > packet->limit ) return ERROR_BUFFER_OVERFLOW;

	/*
	 * Extract all necessary informations from the header to perform sanity,
	 * conformance and bounds checks.
	 */
	header                =  beginHeader;
	hardType              =  decBE16( header->hardAddrType );
	protType              =  decBE16( header->protAddrType );
	hardSize              =  header->hardAddrSize;
	protSize              =  header->protAddrSize;

	/*
	 * Conformance-Check the packet header. Note that only a combination of
	 * Ethernet and IPv4 is supported (for now).
	 */
	if(
		(hardType != 1)||
		(protType == 0x0800)||
		(hardSize != 6)||
		(protSize != 4)
	) return ERROR_PROTOCOL_VIOLATION;

	/*
	 * Extract all informations from the packet header.
	 */
	info->sourcePos                    =  0;
	*((MacAddr*)info->hardAddress[0])  =  *((MacAddr*)header->hardAddrSource);
	info->protAddress[0]               =  header->protAddrSource;
	*((MacAddr*)info->hardAddress[1])  =  *((MacAddr*)header->hardAddrTarget);
	info->protAddress[1]               =  header->protAddrTarget;
	info->opCode                       =  decBE16( header->opCode );

	/*
	 * Keep the old boundaries to the packet. (for now)
	 */
	return 0;
}


