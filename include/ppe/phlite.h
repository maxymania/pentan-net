/*
 * Copyright(C) 2016 Simon Schmidt
 * 
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */
#ifndef PPE_PHLITE_H
#define PPE_PHLITE_H
#include <ppe/stdint.h>

typedef struct {
	/*
	 * The header checksum is stored in an non-inverted format.
	 */
	uint16_t  headerCheckSum;
	/*
	 * On IPv6 pseudoheaders, the TCP-length is represented as 32 bit, but as
	 * 16 bit in IPv4 Pseudoheaders. So we need to notify the checksum generator.
	 */
	uint16_t  modeIsV6;
} IPPH_Info;

#endif

