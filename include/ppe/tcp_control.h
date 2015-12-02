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

typedef struct _TCP_Segment_s TCP_Segment;
struct _TCP_Segment_s {
    TCP_Segment *next; /* The public queue. */
    TCP_Segment *nextInternal; /* The internally used queue. */
    TCP_SegmentInfo header;
    ppeBuffer packet;
	uint16_t frameAck;
	char transmitted;
};

typedef struct {
	TCP_Segment *head;
	TCP_Segment *tail;
} TCP_SegmentQueue;

typedef TCP_Segment *(*TCP_SegmentAllocator)(void* data);

/*
 * @brief TCP protocol Control Block
 *
 *
 * A TCP protocol Control Block. A TCP-PCB handles the state of a TCP-Connection,
 * but NOT for a listening socket.
 */
typedef struct {
	void *allocData;
	TCP_SegmentAllocator alloc;
	/* Ports */
	uint16_t remotePort,localPort;	
	uint16_t sndWnd;
	uint16_t rcvWnd;
	uint32_t sndSeq;
	uint32_t rcvSeq;
	/*
	 * Receive Counter. It is incremented by the TCP logic and must be
	 * decremented, as data has been delivered to the Application.
	 * The Stack maintains this counter in order to know, when to apply
	 * back pressure.
	 */
	uint32_t rcvCtr;

	/* Public queues to peek from: */
	TCP_SegmentQueue output,read,free;

	TCP_SegmentQueue retransmit;

	int phase;
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
	/* TCP connection is DEAD */
	TCPPCB_DEAD        = 0x1,
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

int ppe_tcpPcb_input(TCP_ProtocolControlBlock* pcb, TCP_Segment *input);

int ppe_tcpPcb_write(TCP_ProtocolControlBlock* pcb, TCP_Segment *packet);


#endif


