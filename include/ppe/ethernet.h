/*
 * Copyright(C) 2015 Simon Schmidt
 * 
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */
#ifndef PPE_ETHERNET_H
#define PPE_ETHERNET_H
#include <ppe/stdint.h>
#include <ppe/buffer.h>

typedef uint8_t MacAddress[6];

typedef struct{
	MacAddress remote,local;
	uint16_t type;

	 /* ignored in createPacket */
	uint16_t crcsum;

	 /* ignored in createPacket */
	uint16_t length;
} Eth_FrameInfo;

/*
 * @brief create an Ethernet Frame
 * @param  packet  The Packet Buffer.
 * @param  info    Frame Informations
 * @return 0 on success, !=0 otherwise
 * 
 * This function creates an Ethernet Frame with Mac address.
 * The Frame header will be prepended and the footer will be appended to the
 * ethernet frame.
 */
int ppe_createPacket_eth(ppeBuffer *packet, Eth_FrameInfo *info);

/*
 * @brief Parses an Ethernet Frame
 * @param  packet  The Packet Buffer.
 * @param  info    Frame Informations
 * @return 0 on success, !=0 otherwise
 *
 * This function parses an Ethernet Frame, and extracts the source and destination
 * addresses, as well as the type.
 */
int ppe_parsePacket_eth(ppeBuffer *packet, Eth_FrameInfo *info);

#endif


