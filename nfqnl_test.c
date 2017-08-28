#include "netdefhdr.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

void dump(unsigned char *data, int size){
	printf("EclipseMode dump\n");
	for(int i = 0 ; i < size ; i++){
		printf("%02x ", *data++);
	}
	printf("\n");
}

#include <libnetfilter_queue/libnetfilter_queue.h>

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb, uint8_t *block_packet)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
//		printf("hw_protocol=0x%04x hook=%u id=%u ",
//			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

//		printf("hw_src_addr=");
//		for (i = 0; i < hlen-1; i++)
//			printf("%02x:", hwph->hw_addr[i]);
//		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
//		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
//		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
//		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
//		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
//		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0){
//		printf("payload_len=%d ", ret);
		memcpy(block_packet, data, ret);	
		block_packet[ret] = '\0';
	}

//	fputc('\n', stdout);

	return id;
}	

int	http_checker(uint8_t *block_packet, uint8_t *http_payload){
	uint8_t	*payload;
	uint16_t iphdr_size, tcphdr_size;
	int	http_flag = 1;

	ip_header *ip_hdr;
	tcp_header *tcp_hdr;

	ip_hdr = (ip_header *)block_packet;
	if(ip_hdr -> protocol_id == __TCP_PROTO__){
		iphdr_size = (ip_hdr -> packet_length);
		tcp_hdr = (tcp_header *)(block_packet + iphdr_size);
		tcphdr_size = sizeof(ethernet_header) + iphdr_size + (tcp_hdr -> offset) * 4;
		if((ntohs(tcp_hdr -> dst_port_num) == 80))
			payload = block_packet + iphdr_size + tcphdr_size;
		else http_flag = 0;
	}
	
	if (!http_flag) return 0;
	else {
		http_payload = payload;
		return 1;
	}	
}

int	tcp_checker(uint8_t *block_packet){
	ip_header 	*ip_hdr;
	tcp_header	*tcp_hdr;
	uint8_t *http_payload;
	uint16_t iphdr_size, tcphdr_size;
	int	http_flag = 0;
	int	drop_flag = 0;

	ip_hdr = (ip_header *)(block_packet + sizeof(ethernet_header));
	iphdr_size = ip_hdr -> packet_length;

	tcp_hdr = (tcp_header *)(block_packet + iphdr_size + sizeof(ethernet_header));
	tcphdr_size = sizeof(ethernet_header) + iphdr_size + (tcp_hdr -> offset) * 4;

	http_flag = http_checker(block_packet, http_payload);
	if (!http_flag) return 0;
	else {
		if(strstr((const char*)http_payload, "www.gilgil.net/test") != NULL) return 1;
		else return 0;
	}
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	uint8_t* block_packet;	// MAX MTU LENGTH : 1500 : defined in netdefhdr.h
	u_int32_t id = print_pkt(nfa,block_packet);
	int tcp_checker_flag = tcp_checker(block_packet);
	printf("entering callback\n");
	if(tcp_checker_flag) {
		dump(block_packet,20);
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
	else return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
