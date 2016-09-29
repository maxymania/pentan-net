/*
 * Copyright(C) 2015-2016 Simon Schmidt
 * 
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */
#include <ppe/tcp_control.h>

/*
 * A bitmask for those flags, relevant to TCP connection control.
 */
static const int TCP_CC_RELEVANT = TCPF_FIN|TCPF_SYN|TCPF_RST|TCPF_ACK;

static const int TCP_CC_FINACK = TCPF_FIN|TCPF_ACK;

#define QUEUE_INSERT(queue,element,fnext)   \
	do{                                     \
		element->fnext = 0;                 \
		if( queue.tail ) {                  \
			queue.tail->fnext = element;    \
		}else{                              \
			queue.head = element;           \
			queue.tail = element;           \
		}                                   \
			queue.tail = element;           \
	}while(0)


int ppe_tcpPcb_isAccept(TCP_SegmentInfo *input, TCP_PacketMeta *meta){
	if( ((input->flags)&TCP_CC_RELEVANT) == TCPF_SYN){
		meta->flags = input->flags;
		meta->seq   = input->seq;
		meta->ack   = input->ack;
	}
	return 0;
}

int ppe_tcpPcb_accept(
	TCP_ProtocolControlBlock* pcb,
	TCP_SegmentInfo *output,
	TCP_PacketMeta *meta,
	uint32_t random){
	pcb->phase = TCP_PHASE_ACCEPTING;
	output->flags = TCPF_SYN|TCPF_ACK;
	pcb->rcvSeq = output->ack = meta->seq+1;
	pcb->sndSeq = output->seq = random;
	return 0;
}

int ppe_tcpPcb_connect(
	TCP_ProtocolControlBlock* pcb,
	TCP_SegmentInfo *output,
	uint32_t random){
	pcb->phase = TCP_PHASE_CONNECTING;
	output->flags = TCPF_SYN;
	pcb->sndSeq = output->seq = random;
	return 0;
}


int ppe_tcpPcb_input(TCP_ProtocolControlBlock* pcb,TCP_Segment *input){
	TCP_Segment *output;
	TCP_SegmentInfo *inputHead = &(input->header);
	uintptr_t length = ((input->packet.limit)-(input->packet.position));
	int result = 0;
	#define ADDRESULT(x) result|=x
	#define REMRESULT(x) result&=~x

	if(  (inputHead->flags)&TCPF_RST  ){
		pcb->phase = TCP_PHASE_DEAD;
		ADDRESULT(TCPPCB_DEAD);
		QUEUE_INSERT(pcb->free,input,next);
		return result;
	}
	switch(pcb->phase){
	case TCP_PHASE_ESTABLISHED:
		switch( (inputHead->flags) & TCP_CC_RELEVANT ) {
		case TCPF_FIN:
			pcb->phase                = TCP_PHASE_PASSIVE_CLOSE;
			output                    = pcb->alloc(pcb->allocData); output->header.sourcePos = 0;
			output->header.ports[0]  = pcb->localPort;
			output->header.ports[1] = pcb->remotePort;
			output->header.flags      = TCPF_ACK;
			output->header.ack        = inputHead->seq+1;
			output->header.seq        = inputHead->ack+1;
			output->header.windowSize = pcb->rcvWnd;
			QUEUE_INSERT(pcb->output,output,next);
			output                    = pcb->alloc(pcb->allocData); output->header.sourcePos = 0;

			output->header.ports[0]  = pcb->localPort;
			output->header.ports[1] = pcb->remotePort;
			output->header.flags      = TCPF_FIN;
			output->header.ack        = inputHead->seq+1;
			output->header.seq        = inputHead->ack+1;
			output->header.windowSize = pcb->rcvWnd;
			QUEUE_INSERT(pcb->output,output,next);
			QUEUE_INSERT(pcb->free,input,next);
			return result;
		}
		
		if( (inputHead->flags) & TCPF_ACK ){
			/*
			 * Remove all packets packets from the queue, that have the
			 * calculated ACK number below the given one from the recieved packet.
			 */
			while( pcb->retransmit.head &&
				( (pcb->retransmit.head->frameAck) <=
				(inputHead->ack) ) ) {
				output = pcb->retransmit.head;
				
				QUEUE_INSERT(pcb->free,output,next);
				
				/*
				 * Shift to the next one.
				 */
				pcb->retransmit.head = output->nextInternal;
			}
			output = pcb->retransmit.head;
			if( output )
				/*
				 * Retransmit the last packet in the queue.
				 */
				QUEUE_INSERT(pcb->output,output,next);
			else
				/*
				 * Set the tail to 0
				 */
				pcb->retransmit.tail = 0;
			
			QUEUE_INSERT(pcb->free,input,next);
		}
		/*
		 * When the packet contains data.
		 */
		if( length>0 ) {
			if( inputHead->seq < pcb->rcvSeq ){
				QUEUE_INSERT(pcb->free,input,next);
				output                    = pcb->alloc(pcb->allocData); output->header.sourcePos = 0;
				output->header.ports[0]  = pcb->localPort;
				output->header.ports[1] = pcb->remotePort;
				output->header.flags      = TCPF_ACK;
				output->header.ack        = pcb->rcvSeq;
				output->header.seq        = pcb->sndSeq;
				// TODO: calculate remaining receive window size
				output->header.windowSize = pcb->rcvWnd;
				QUEUE_INSERT(pcb->output,output,next);
			} else if( inputHead->seq == pcb->rcvSeq ) {
				QUEUE_INSERT(pcb->read,input,next);
				pcb->rcvSeq += length;
				pcb->rcvCtr += length;
				output                    = pcb->alloc(pcb->allocData); output->header.sourcePos = 0;
				output->header.ports[0]  = pcb->localPort;
				output->header.ports[1] = pcb->remotePort;
				output->header.flags      = TCPF_ACK;
				output->header.ack        = pcb->rcvSeq;
				output->header.seq        = pcb->sndSeq;
				// TODO: calculate remaining receive window size
				output->header.windowSize = pcb->rcvWnd;
				QUEUE_INSERT(pcb->output,output,next);
			} else {
				QUEUE_INSERT(pcb->free,input,next);
				// TODO: (proper) TCP HANDLING
			}
		}
		
		return result;
	case TCP_PHASE_ACCEPTING:
		switch( (inputHead->flags) & TCP_CC_RELEVANT ){
		case TCPF_ACK:
			pcb->phase                = TCP_PHASE_ESTABLISHED;
			pcb->rcvSeq               = inputHead->seq;
			pcb->sndSeq               = inputHead->ack;
			// TODO: TCP-Fast-Open
			break;
		}
		break;
	case TCP_PHASE_CONNECTING:
		switch( (inputHead->flags) & TCP_CC_RELEVANT ){
		case TCPF_SYN|TCPF_ACK:
			pcb->phase                = TCP_PHASE_ESTABLISHED;
			output                    = pcb->alloc(pcb->allocData); output->header.sourcePos = 0;
			output->header.ports[0]  = pcb->localPort;
			output->header.ports[1] = pcb->remotePort;
			output->header.flags      = TCPF_ACK;
			// TODO: Seq/Ack-number-checks?
			pcb->rcvSeq = output->header.ack = inputHead->seq+1;
			pcb->sndSeq = output->header.seq = inputHead->ack+1;
			output->header.windowSize = pcb->rcvWnd;
			QUEUE_INSERT(pcb->output,output,next);
			break;
		}
		break;
	case TCP_PHASE_ACTIVE_CLOSE:
		// TODO: Seq/Ack-number-checks?
		pcb->finack |= inputHead->flags;
		if( (inputHead->flags) & TCPF_FIN ) {
			pcb->phase                = TCP_PHASE_ESTABLISHED;
			output                    = pcb->alloc(pcb->allocData); output->header.sourcePos = 0;
			output->header.ports[0]  = pcb->localPort;
			output->header.ports[1] = pcb->remotePort;
			output->header.flags      = TCPF_ACK;
			output->header.ack        = inputHead->seq+1;
			output->header.seq        = inputHead->ack+1;
			output->header.windowSize = pcb->rcvWnd;
			QUEUE_INSERT(pcb->output,output,next);
			break;
		}
		if( ( (pcb->finack)&TCP_CC_FINACK ) == TCP_CC_FINACK ){
			pcb->phase                = TCP_PHASE_DEAD;
			ADDRESULT(TCPPCB_DEAD);
			break;
		}
		break;
	case TCP_PHASE_PASSIVE_CLOSE:
		switch( (inputHead->flags) & TCP_CC_RELEVANT ){
		case TCPF_ACK:
			pcb->phase                = TCP_PHASE_DEAD;
			ADDRESULT(TCPPCB_DEAD);
			break;
		}
		break;
	}
	QUEUE_INSERT(pcb->free,input,next);
	return result;
	#undef ADDRESULT
	#undef REMRESULT
}

int ppe_tcpPcb_write(TCP_ProtocolControlBlock* pcb, TCP_Segment *packet){
	// TODO: (proper) TCP HANDLING
	QUEUE_INSERT(pcb->output,packet,next);
	QUEUE_INSERT(pcb->retransmit,packet,nextInternal);
	// TODO: (proper) TCP HANDLING
	return 0;
}



