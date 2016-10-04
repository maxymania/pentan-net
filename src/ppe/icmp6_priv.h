/*
 * Copyright(C) 2016 Simon Schmidt
 * 
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */


/* ICMPv6 Error Messages */
#define ICMPv6_DEST_UNREACH    1   /* Destination Unreachable */
#define ICMPv6_PACKET_TOO_BIG  2   /* Packet Too Big */
#define ICMPv6_TIMXCEED        3   /* Time Exceeded */
#define ICMPv6_PARAM_PROBLEM   4   /* Parameter Problem */

/* - Destination Unreachable */
#define ICMPv6_DEST_UNREACH_NO_ROUTE     0  /* no route to destination */
#define ICMPv6_DEST_UNREACH_PROHIB       1  /* communication with destination administratively prohibited */
#define ICMPv6_DEST_UNREACH_BEYOND_SCOPE 2  /* beyond scope of source address */
#define ICMPv6_DEST_UNREACH_HOST         3  /* address unreachable */
#define ICMPv6_DEST_UNREACH_PORT         4  /* port unreachable */
#define ICMPv6_DEST_UNREACH_POLICY_FAIL  5  /* source address failed ingress/egress policy */
#define ICMPv6_DEST_UNREACH_ROUTE_REJECT 6  /* reject route to destination */
#define ICMPv6_DEST_UNREACH_HEADER       7  /* Error in Source Routing Header */

/* - Time Exceeded */
#define ICMPv6_TIMXCEED_HOP_LIMIT 0  /* hop limit exceeded in transit */
#define ICMPv6_TIMXCEED_FRAGMENT  1  /* fragment reassembly time exceeded */

/* - Parameter Problem */
#define ICMPv6_PARAM_PROBLEM_HEADER      0  /* erroneous header field encountered */
#define ICMPv6_PARAM_PROBLEM_NEXT_HEADER 1  /* unrecognized Next Header type encountered */
#define ICMPv6_PARAM_PROBLEM_OPTION      2  /* unrecognized IPv6 option encountered */

/* ICMPv6 Informational Messages */

/* - ICMPv6 echo */
#define ICMPv6_ECHO_REQUEST 128
#define ICMPv6_ECHO_REPLY   129

/* - Multicast Listener Query */
#define ICMPv6_MLD_QUERY    130
#define ICMPv6_MLD_REPORT   131
#define ICMPv6_MLD_DONE     132

/* - Neighbor Discovery Protocol */
#define ICMPv6_NDP_ROUTER_SOLICIT    133
#define ICMPv6_NDP_ROUTER_ADVERT     134
#define ICMPv6_NDP_NEIGHBOR_SOLICIT  135
#define ICMPv6_NDP_NEIGHBOR_ADVERT   136
#define ICMPv6_NDP_REDIRECT          137


/* The default MTU in IPv6 */
#define IPv6_DEFAULT_MTU    1280


