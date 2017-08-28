#include <stdint.h>

#define	__ETHER_IP__	0x0800
#define	__ETHER_ARP__	0x0806

#define __IP_PROTO__	0
#define __ICMP_PROTO__	1
#define __TCP_PROTO__	6

#define __ETHERNET_HWLEN__ 6

#define __MAX_MTU__ 1500

typedef struct __ethernet_header__{
	uint8_t		src_hw_addr[__ETHERNET_HWLEN__];
	uint8_t		dst_hw_addr[__ETHERNET_HWLEN__];
	uint16_t	type;
}ethernet_header;

typedef struct __ip_header__{
	uint8_t		ver_hlen;
	uint8_t		type_of_service;
	uint16_t	packet_length;
	uint16_t	identifier;
	uint16_t	offset;
	uint8_t		time_to_live;
	uint8_t		protocol_id;
	uint16_t	checksum;
	uint32_t	src_ip_addr;
	uint32_t	dst_ip_addr;	
}ip_header;

typedef struct __tcp_header__{
	uint16_t	src_port_num;
	uint16_t	dst_port_num;
	uint32_t	sequence_num;
	uint32_t	ack_num;
	uint8_t		offset;
	uint8_t		flags;
	uint16_t	window_size;
	uint16_t	checksum;
	uint16_t	urgent_pointer;
}tcp_header;

typedef enum {false, true} bool;
