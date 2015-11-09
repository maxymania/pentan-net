/*
 * Copyright(C) 2015 Simon Schmidt
 * 
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */
#ifndef PPE_TCP_CONTROL_H
#define PPE_TCP_CONTROL_H
#include <ppe/tcp.h>

/*
 * @brief TCP protocol Control Block
 *
 *
 * A TCP protocol Control Block. A TCP-PCB handles the state of a TCP-Connection,
 * but NOT for a listening socket.
 */
typedef struct {
	int state;
} TCP_ProtocolControlBlock;

/*
 * NOTE THAT: This file is still experimental.
 */

enum{
	TcpPcbCmd_Nop, /* NO-OP */
	TcpPcbCmd_Close,
	TcpPcbCmd_Listen,
	TcpPcbCmd_Connect
};
enum{
	TCPPCB_INPUT_OUTPUT = 1,
	TCPPCB_INPUT_CLOSE = 2,
};

int ppe_tcpPcb_input(
	TCP_ProtocolControlBlock* tsa,
	int cmd,
	ppeBuffer *packet,
	TCP_SegmentInfo *input,
	TCP_SegmentInfo *output
);

#endif


