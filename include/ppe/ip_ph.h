/*
 * Copyright(C) 2015 Simon Schmidt
 * 
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */
#ifndef PPE_IP_PSEUDOHEADER_H
#define PPE_IP_PSEUDOHEADER_H
#include <ppe/ipv4.h>
#include <ppe/ipv6.h>

/*
 * This source module carries structures, that are used in order to carry
 * the IP informations, needed to calculate the IP Pseudo-Header Informations
 * required by the TCP- or UDP- protocols.
 */

enum {
	IPPH_IPv4 = 4;
	IPPH_IPv6 = 6;
};

struct {
	uint8_t ipphType = 0;
	union {
		IPV4_PacketInfo ipv4;
		IPV6_PacketInfo ipv6;
	};
} IPPH_Struct;


#endif

