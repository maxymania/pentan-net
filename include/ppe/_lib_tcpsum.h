/*
 * Copyright (C) 2016 Simon Schmidt
 * 
 * You may use this program, or code extracted from it, as desired without
 * restriction.
 * 
 * If this license is not concise enough you may also use it under the terms
 * of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
 * distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */

#include <ppe/stdint.h>

static inline
uint16_t tcp_checksum(const uint16_t* buffer, int words)
{
	uint32_t check = 0;
	int i = words;
	for(;i>0;--i,++buffer)check+=*buffer;
	/* while(check>>16) check = (check&0xffff)+(check>>16); */
	check = (check&0xffff)+(check>>16);
	check = (check&0xffff)+(check>>16);
	return ~check;
}


