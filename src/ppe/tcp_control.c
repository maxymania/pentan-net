/*
 * Copyright(C) 2015 Simon Schmidt
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
	pcb->state = TCP_PHASE_ACCEPTING;
	output->flags = TCPF_SYN|TCPF_ACK;
	output->ack = meta->seq+1;
	output->seq = random;
	return 0;
}

int ppe_tcpPcb_connect(
	TCP_ProtocolControlBlock* pcb,
	TCP_SegmentInfo *output,
	uint32_t random){
	pcb->state = TCP_PHASE_CONNECTING;
	output->flags = TCPF_SYN;
	output->seq = random;
	return 0;
}


int ppe_tcpPcb_input(TCP_ProtocolControlBlock* pcb,TCP_SegmentInfo *input,ppeBuffer *packet){
	int result = 0;
	#define ADDRESULT(x) result|=x
	#define REMRESULT(x) result&=~x
	if(pcb->meta)
		ADDRESULT(TCPPCB_OUTPUT_MORE);
	if(  (input->flags)&TCPF_RST  ){
		pcb->phase = TCP_PHASE_DEAD;
		ADDRESULT(TCPPCB_DEAD);
		return result;
	}
	switch(pcb->phase){
	case TCP_PHASE_ESTABLISHED:
		switch( (input->flags) & TCP_CC_RELEVANT ) {
		case TCPF_FIN:
			pcb->phase      = TCP_PHASE_PASSIVE_CLOSE;
			pcb->res.flags  = TCPF_ACK;
			pcb->res.ack    = input->seq+1;
			pcb->res.seq    = input->ack+1;
			pcb->res2.flags = TCPF_FIN;
			pcb->res2.ack   = input->seq+1;
			pcb->res2.seq   = input->ack+1;
			pcb->meta      |= TCPMETA_RES|TCPMETA_RES2;
			ADDRESULT(TCPPCB_OUTPUT_MORE);
			break;
		}
		
		// TODO: TCP HANDLING
		return result;
	case TCP_PHASE_ACCEPTING:
		switch( (input->flags) & TCP_CC_RELEVANT ){
		case TCPF_ACK:
			pcb->phase      = TCP_PHASE_ESTABLISHED;
			// TODO: TCP-Fast-Open
			break;
		}
		break;
	case TCP_PHASE_CONNECTING:
		switch( (input->flags) & TCP_CC_RELEVANT ){
		case TCPF_SYN|TCPF_ACK:
			pcb->phase      = TCP_PHASE_ESTABLISHED;
			pcb->res.flags  = TCPF_ACK;
			pcb->res.ack    = input->seq+1;
			pcb->res.seq    = input->ack+1;
			pcb->meta      |= TCPMETA_RES;
			ADDRESULT(TCPPCB_OUTPUT_MORE);
			break;
		}
		break;
	case TCP_PHASE_ACTIVE_CLOSE:
		pcb->finack |= input->flags;
		if( (input->flags) & TCPF_FIN ) {
			pcb->phase      = TCP_PHASE_ESTABLISHED;
			pcb->res.flags  = TCPF_ACK;
			pcb->res.ack    = input->seq+1;
			pcb->res.seq    = input->ack+1;
			pcb->meta      |= TCPMETA_RES;
			ADDRESULT(TCPPCB_OUTPUT_MORE);
			break;
		}
		if( ( (pcb->finack)&TCP_CC_FINACK ) == TCP_CC_FINACK ){
			pcb->phase = TCP_PHASE_DEAD;
			ADDRESULT(TCPPCB_DEAD);
			break;
		}
		break;
	case TCP_PHASE_PASSIVE_CLOSE:
		switch( (input->flags) & TCP_CC_RELEVANT ){
		case TCPF_ACK:
			pcb->phase      = TCP_PHASE_DEAD;
			ADDRESULT(TCPPCB_DEAD);
			break;
		}
		break;
	}
	ADDRESULT(TCPPCB_DEAD);
	return result;
	#undef ADDRESULT
	#undef REMRESULT
}

int ppe_tcpPcb_output(TCP_ProtocolControlBlock* pcb,TCP_SegmentInfo *output,ppeBuffer *packet){
	int meta = pcb->meta;
	#define TCPMETA(field,name)                   \
		if(meta&TCPMETA_##name){                  \
			output->flags = pcb->field.flags;     \
			output->ack   = pcb->field.ack;       \
			output->seq   = pcb->field.seq;       \
			pcb->meta = meta & ~TCPMETA_##name;   \
			return TCPPCB_OUTPUT_OK|              \
				(pcb->meta?TCPPCB_OUTPUT_MORE:0); \
		}
	TCPMETA(res,RES);
	TCPMETA(res2,RES2);
	#undef TCPMETA
	return 0;
}

int ppe_tcpPcb_free(TCP_ProtocolControlBlock* pcb, ppeBuffer **packet);
int ppe_tcpPcb_read(TCP_ProtocolControlBlock* pcb, ppeBuffer **packet);
int ppe_tcpPcb_write(TCP_ProtocolControlBlock* pcb, ppeBuffer *packet);


