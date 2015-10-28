/*
 * Copyright(C) 2015 Simon Schmidt
 * 
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */
#ifndef PPE_ENDIANESS_H
#define PPE_ENDIANESS_H
#include <ppe/stdint.h>

#ifdef HOST_ENDIAN_LITTLE

#ifndef FAST_BYTE_SWAP
inline uint16_t encBE16(uint16_t t){
	return (t>>8) | (t<<8);
}

inline uint16_t decBE16(uint16_t t){
	return (t>>8) | (t<<8);
}

inline uint32_t encBE32(uint32_t t){
	return (t>>24)&0xff) | ((t<<8)&0xff0000) | ((t>>8)&0xff00) | ((t<<24)&0xff000000);
}

inline uint32_t decBE32(uint32_t t){
	return (t>>24)&0xff) | ((t<<8)&0xff0000) | ((t>>8)&0xff00) | ((t<<24)&0xff000000);
}

#else /* FAST_BYTE_SWAP */
#include <byteswap.h>

#define encBE16(i) __bswap_16(i)
#define decBE16(i) __bswap_16(i)
#define encBE32(i) __bswap_32(i)
#define decBE32(i) __bswap_32(i)

#endif /* FAST_BYTE_SWAP */

#else /* HOST_ENDIAN_LITTLE */

#define encBE16(i) (i)
#define decBE16(i) (i)
#define encBE32(i) (i)
#define decBE32(i) (i)

#endif /* HOST_ENDIAN_LITTLE */

#endif

