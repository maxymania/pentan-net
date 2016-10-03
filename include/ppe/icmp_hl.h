/*
 * Copyright(C) 2016 Simon Schmidt
 * 
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */
#ifndef PPE_ICMPHL_H
#define PPE_ICMPHL_H
#include <ppe/stdint.h>
#include <ppe/icmp4.h>
#include <ppe/icmp6.h>

enum ICMP_Action {
	ICMPA_None, /* Drop */
	ICMPA_Reply,
	ICMPA_Input,
	ICMPA_Transport, /* Forward to Transport Layer */
	ICMPA_Internet, /* Forward to Internet Layer */
	ICMPA_Router, /* Forward to Router Subsystem, if any */
};

enum ICMP_Code {
	ICMP_Generic, /* No or neutral meaning. */
	ICMP_Echo,
	ICMP_Error_UnreachableNet,
	ICMP_Error_UnreachableHost,
	ICMP_Error_UnreachableProtocol,
	ICMP_Error_UnreachablePort,
	ICMP_Error_UnreachableSource,
	ICMP_Error_Congestion,
	ICMP_Error_BadHeader,
	ICMP_Error_MessageSizeTooBig,
	ICMP_Info_RouterAdvertisement,
	ICMP_Info_RouterSolicitation,
	ICMP_Info_NeighborAdvertisement,
	ICMP_Info_NeighborSolicitation,
};

typedef struct{
	enum ICMP_Action  command;
	enum ICMP_Code    code;
	uint8_t           protoc;
} ICMP_Command;

/*
 * @brief makes an Decision regarding ICMPv4.
 * @param  packet  The Packet Buffer.
 * @param  info    Frame Informations
 * @return 0 on success, !=0 otherwise
 * 
 * This function makes an Decision regarding an incoming ICMPv4 message.
 */
int ppe_inputCtrl_icmp4(ICMPv4_Arguments *info, ICMP_Command* cmd);


#endif


