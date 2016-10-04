/*
 * Copyright(C) 2016 Simon Schmidt
 * 
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */
#include <ppe/ipv6_ext.h>
#include <ppe/errornum.h>
#include <ppe/endianess.h>

typedef void* Pointer;
typedef uint8_t* BytePtr;

#define P(x) ((void*)(x))

int ppe_jumpExtensions_ipv6(uint8_t* nextHeader, void** position, void* limit){
	uint8_t nh;
	BytePtr pos;
	Pointer lookahead; /* Lookahead-limit */

	/*
	 * This function has a Lookahead of 2 bytes.
	 */
	lookahead = limit-2;

	nh  = *nextHeader;
	pos = *position;
	if( P(pos) > limit ) return ERROR_BUFFER_OVERFLOW;


	for(;;){
		switch( nh ){
		case 0:    /* Hop-by-Hop Options */
		case 0x2B: /* Routing Header */
		case 0x3C: /* Destination Options for IPv6 */
		case 0x87: /* Mobility Extension Header for IPv6 */
			if( P(pos) > lookahead ) return ERROR_BUFFER_OVERFLOW;

			nh   = *pos;
			pos +=  pos[1];

			/*
			 * Check if we have an buffer overrunn.
			 */
			if( P(pos) > limit ) return ERROR_BUFFER_OVERFLOW;

			continue;

		case 0x2C: /* IPv6-Fragment */
			if( P(pos) > (limit-4) ) return ERROR_BUFFER_OVERFLOW;

			/*
			 * Check if we got the first fragment.
			 */
			if( decBE16(*((uint16_t*)(pos+2)))>>3 ) return ERROR_NO_PAYLOAD;

			nh   = *pos;
			pos += 8;

			/*
			 * Check if we have an buffer overrunn.
			 */
			if( P(pos) > limit ) return ERROR_BUFFER_OVERFLOW;
		case 0x3B: /* No Next Header (Packet empty) */
			return ERROR_NO_PAYLOAD;
		}
		break;
	}
	*nextHeader = nh;
	*position   = pos;
	return 0;
}

