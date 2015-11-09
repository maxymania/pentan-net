/*
 * Copyright(C) 2015 Simon Schmidt
 * 
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */
#include <ppe/tcp_control.h>

enum {
	CLOSED,
	LISTEN,
	SYN_SENT,
	SYN_RECIEVED,
	ESTABLISHED,
	FIN_WAIT_1,
	FIN_WAIT_2,
	CLOSE_WAIT,
	CLOSING,
	LAST_ACK,
	TIME_WAIT
};

/*
 * A bitmask for those flags, relevant to TCP connection control.
 */
static const int TCP_CC_RELEVANT = TCPF_FIN|TCPF_SYN|TCPF_RST|TCPF_ACK;

/*
 * NOTE THAT: This file is still experimental.
 *
 * Currently, I just implemented a State Automaton, that controls the
 * Connect- and Deconnect- phase.
 */


int ppe_tcpPcb_input(
	TCP_ProtocolControlBlock* pcb,
	int cmd,
	ppeBuffer *packet,
	TCP_SegmentInfo *input,
	TCP_SegmentInfo *output
){
	if(cmd==TcpPcbCmd_Close) {
		switch(pcb->state){
		case LISTEN:
		case SYN_SENT:
			pcb->state = CLOSED;
			return 0;
		case SYN_RECIEVED:
		case ESTABLISHED:
			pcb->state = FIN_WAIT_1;
			output->flags = TCPF_FIN;
			return TCPPCB_INPUT_OUTPUT;
		case CLOSE_WAIT:
			pcb->state = LAST_ACK;
			output->flags = TCPF_FIN;
			return TCPPCB_INPUT_OUTPUT;
		}
	}

	switch(pcb->state){
	case CLOSED:
		switch(cmd){
		case TcpPcbCmd_Listen:
			pcb->state = LISTEN;
			return 0;
		case TcpPcbCmd_Connect:
			pcb->state = SYN_SENT;
			output->flags = TCPF_SYN;
			output->seq = 123; // TODO: random number
			return TCPPCB_INPUT_OUTPUT;
		}
		return 0;
	case LISTEN:
		if(cmd!=0) return 0;
		switch( (input->flags) & TCP_CC_RELEVANT ){
		case TCPF_SYN:
			pcb->state = SYN_RECIEVED;
			output->flags = TCPF_SYN|TCPF_ACK;
			output->ack = input->seq+1;
			output->seq = 321; // TODO: random number
			return TCPPCB_INPUT_OUTPUT;
		}
		return 0;
	case SYN_SENT:
		if(cmd!=0) return 0;
		switch( (input->flags) & TCP_CC_RELEVANT ){
		case TCPF_SYN|TCPF_ACK:
			pcb->state = ESTABLISHED;
			output->flags = TCPF_ACK;
			output->ack = input->seq+1;
			output->seq = input->ack+1;
			return TCPPCB_INPUT_OUTPUT;
		}
		return 0;
	case SYN_RECIEVED:
		if(cmd!=0) return 0;
		switch( (input->flags) & TCP_CC_RELEVANT ){
		case TCPF_ACK:
			pcb->state = ESTABLISHED;
			return TCPPCB_INPUT_OUTPUT;
		}
		return 0;
	case ESTABLISHED:
		if(cmd!=0) return 0;
		switch( (input->flags) & TCP_CC_RELEVANT ) {
		case TCPF_FIN:
			pcb->state = CLOSE_WAIT;
			output->flags = TCPF_ACK;
			output->ack = input->seq+1;
			output->seq = input->ack+1;
			return TCPPCB_INPUT_OUTPUT|TCPPCB_INPUT_CLOSE;
		}
		return 0;
	case LAST_ACK:
		if(cmd!=0) return 0;
		switch( (input->flags) & TCP_CC_RELEVANT ) {
		case TCPF_ACK:
			pcb->state = CLOSED;
			return TCPPCB_INPUT_OUTPUT;
		}
		return 0;
	case CLOSING:
		if(cmd!=0) return 0;
		switch( (input->flags) & TCP_CC_RELEVANT ) {
		case TCPF_ACK:
			pcb->state = TIME_WAIT;
			return TCPPCB_INPUT_OUTPUT;
		}
		return 0;
	case FIN_WAIT_1:
		if(cmd!=0) return 0;
		switch( (input->flags) & TCP_CC_RELEVANT ) {
		case TCPF_ACK:
			pcb->state = FIN_WAIT_2;
			return 0;
		case TCPF_FIN:
			pcb->state = CLOSING;
			output->flags = TCPF_ACK;
			output->ack = input->seq+1;
			output->seq = input->ack+1;
			return TCPPCB_INPUT_OUTPUT;
		case TCPF_FIN|TCPF_ACK:
			pcb->state = TIME_WAIT;
			output->flags = TCPF_ACK;
			output->ack = input->seq+1;
			output->seq = input->ack+1;
			return TCPPCB_INPUT_OUTPUT;
		}
	case FIN_WAIT_2:
		if(cmd!=0) return 0;
		switch( (input->flags) & TCP_CC_RELEVANT ) {
		case TCPF_FIN:
			pcb->state = TIME_WAIT;
			output->flags = TCPF_ACK;
			output->ack = input->seq+1;
			output->seq = input->ack+1;
			return TCPPCB_INPUT_OUTPUT;
		}
		return 0;
	}
	return 0;
}



