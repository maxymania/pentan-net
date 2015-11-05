#include <ppe/ip_ph.h>
#include <ppe/endianess.h>

/*
 *             Figure 1: IPv4 pseudo header
 *
 *   0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                       Source Address                          |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                    Destination Address                        |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |     Zeros     |    Protocol   |          TCP Length           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 *
 *             Figure 2: IPv6 pseudo header
 *
 *   0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   |                                                               |
 *   |                                                               |
 *   |                       Source Address                          |
 *   |                                                               |
 *   |                                                               |
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   |                                                               |
 *   |                                                               |
 *   |                    Destination Address                        |
 *   |                                                               |
 *   |                                                               |
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                          TCP Length                           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                    Zeros                      |    Protocol   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */


// TODO: Comments.
uint64_t ppe_ipphChecksum(IPPH_Struct *ipph, uintptr_t size){
	uint64_t checksum = 0;
	uint16_t *ptr = 0;
	int i;

	switch(ipph->ipphType){
	case IPPH_IPv4:
		checksum += (ipph->ipv4.remote&0xffff) + ((ipph->ipv4.remote>>16)&0xffff);
		checksum += (ipph->ipv4.local&0xffff) + ((ipph->ipv4.local>>16)&0xffff);
		checksum += ipph->ipv4.protocol;
		checksum += encBE16(size&0xffff);
		break;
	case IPPH_IPv6:
		ptr = (uint16_t*) ipph->ipv6.remote;
		for(i = 0;i < 16; ++i) checksum += ptr[i];
		ptr = (uint16_t*) ipph->ipv6.local;
		for(i = 0;i < 16; ++i) checksum += ptr[i];
		checksum += encBE16(size&0xffff);
		checksum += encBE16((size>>16)&0xffff);
		checksum += ipph->ipv4.protocol;
		break;
	}

	/*
	 * When in doubt, produce the hash of an empty string.
	 */
	return checksum;
}


