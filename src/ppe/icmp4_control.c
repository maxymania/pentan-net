/*
 * Copyright(C) 2016 Simon Schmidt
 * 
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */
#include <ppe/icmp_hl.h>

int ppe_inputCtrl_icmp4(ICMPv4_Arguments *info, ICMP_Command* cmd){
	cmd->command = ICMPA_None;
	cmd->code = ICMP_Generic;
	switch( info->messageType ){
	case ICMPv4_Msg_Request:
		cmd->command = ICMPA_Reply;
		break;
	case ICMPv4_Msg_Response:
		cmd->command = ICMPA_Input;
		break;
	}
	switch( info->mesgMeaning ){
	case ICMPv4_Mng_Echo:
		cmd->code = ICMP_Echo;
		break;
	case ICMPv4_Mng_SourceQuench:
		cmd->command = ICMPA_Transport;
		cmd->code = ICMP_Error_Congestion;
		break;
	case ICMPv4_Mng_UnreachableNet:
		cmd->command = ICMPA_Transport;
		cmd->code = ICMP_Error_UnreachableNet;
		break;
	case ICMPv4_Mng_UnreachableHost:
		cmd->command = ICMPA_Transport;
		cmd->code = ICMP_Error_UnreachableHost;
		break;
	case ICMPv4_Mng_UnreachableProtocol:
		cmd->command = ICMPA_Transport;
		cmd->code = ICMP_Error_UnreachableProtocol;
		break;
	case ICMPv4_Mng_UnreachablePort:
		cmd->command = ICMPA_Transport;
		cmd->code = ICMP_Error_UnreachablePort;
		break;
	case ICMPv4_Mng_UnreachableSource:
		cmd->command = ICMPA_Transport;
		cmd->code = ICMP_Error_UnreachableSource;
		break;

	/*
	 * XXX: Should the Internet Layer or the Transport Layer be notified?
	 */
	case ICMPv4_Mng_ParameterProblems:
		cmd->command = ICMPA_Internet;
		cmd->code = ICMP_Error_BadHeader;
		break;

	case ICMPv4_Mng_MessageSizeTooBig:
		cmd->command = ICMPA_Transport;
		cmd->code = ICMP_Error_MessageSizeTooBig;
		break;
	case ICMPv4_Mng_RouterAdvertisement:
		cmd->command = ICMPA_Internet;
		cmd->code = ICMP_Info_RouterAdvertisement;
		break;
	case ICMPv4_Mng_RouterSolicitation:
		cmd->command = ICMPA_Router;
		cmd->code = ICMP_Info_RouterSolicitation;
		break;
	}
	return 0;
}


