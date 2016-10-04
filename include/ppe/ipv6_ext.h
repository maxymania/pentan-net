/*
 * Copyright(C) 2016 Simon Schmidt
 * 
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */
#ifndef PPE_IPV6_EXT_H
#define PPE_IPV6_EXT_H
#include <ppe/stdint.h>

int ppe_jumpExtensions_ipv6(uint8_t* nextHeader, void** position, void* limit);


#endif


