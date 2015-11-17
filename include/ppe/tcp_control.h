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
 * @brief TCP packet substrate
 */
typedef struct {
	uint32_t  seq;
	uint32_t  ack;
	uint16_t  flags;
} TCP_PacketMeta;

/*
 * @brief TCP protocol Control Block
 *
 *
 * A TCP protocol Control Block. A TCP-PCB handles the state of a TCP-Connection,
 * but NOT for a listening socket.
 */
typedef struct {
	int lastFlags;
	int phase;
	int state;
	int meta;
	TCP_PacketMeta res,res2;
	uint16_t finack;
} TCP_ProtocolControlBlock;

enum{
	TCP_PHASE_ESTABLISHED,
	TCP_PHASE_ACCEPTING,
	TCP_PHASE_CONNECTING,
	TCP_PHASE_ACTIVE_CLOSE,
	TCP_PHASE_PASSIVE_CLOSE,

	/* TCP connection is DEAD */
	TCP_PHASE_DEAD,
};

enum{
	TCPMETA_RES     = 1,
	TCPMETA_RES2    = 2,
};


enum{
	TCPPCB_OUTPUT_OK   = 1,
	TCPPCB_FREE_OK     = 2,
	TCPPCB_READ_OK     = 4,
	TCPPCB_WRITE_OK    = 8,
	TCPPCB_OUTPUT_MORE = 0x10,
	TCPPCB_FREE_MORE   = 0x20,
	TCPPCB_READ_MORE   = 0x40,
	TCPPCB_WRITE_MORE  = 0x80,

	/* TCP connection is DEAD */
	TCPPCB_DEAD        = 0x100,
};


int ppe_tcpPcb_isAccept(TCP_SegmentInfo *input, TCP_PacketMeta *meta);

int ppe_tcpPcb_accept(
	TCP_ProtocolControlBlock* pcb,
	TCP_SegmentInfo *output,
	TCP_PacketMeta *meta,
	uint32_t random);

int ppe_tcpPcb_connect(
	TCP_ProtocolControlBlock* pcb,
	TCP_SegmentInfo *output,
	uint32_t random);

int ppe_tcpPcb_input(TCP_ProtocolControlBlock* pcb, TCP_SegmentInfo *input, ppeBuffer *packet);
int ppe_tcpPcb_output(TCP_ProtocolControlBlock* pcb, TCP_SegmentInfo *output, ppeBuffer *packet);

int ppe_tcpPcb_free(TCP_ProtocolControlBlock* pcb, ppeBuffer **packet);
int ppe_tcpPcb_read(TCP_ProtocolControlBlock* pcb, ppeBuffer **packet);
int ppe_tcpPcb_write(TCP_ProtocolControlBlock* pcb, ppeBuffer *packet);


#endif


