#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>

char bcastmac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

#define CT_IF "ct0.4094"

#define GFASTTYPE 0x22e3
#define GFAST_SN_DISCOVERY 1
#define DFE_DISC_READMEM_LEN 64
#define GFAST_DFE_MEMADDR_CHIP_INFO 0xE1000000
#define gfast_opcode_memread 3
#define GFAST_FRAME_MIN_LEN  (ETH_ZLEN - ETH_HLEN)

struct gfast_mngm_hdr {
    uint16_t      opcode;   /* gfast operation code */
    uint16_t      len;      /* length of the payload after the header(<=1486)  */
    uint16_t      seqNum;
    //u16      reserved; /* TODO!!! The 2 bytes are planned to be used for*/
                         /* indication of the last ack and ack counter    */
                         /* rsrv1 and rsrv2 are temporary names           */
    uint8_t       rsrv1;  /* 1 - it is the last ack, 0 - more acks are expected*/
    uint8_t       rsrv2;  /* Ack counter (max value is 16)   */

    uint32_t      opAddr; /* 4-byte memory address on the DFE device */
} __attribute__((packed));

struct my_packet {
	struct ether_header eh;
	struct gfast_mngm_hdr gh;
	char data[0];
};

int main(int argc, char *argv[])
{
	int sockfd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	//int tx_len = 0;
	//char sendbuf[BUF_SIZ];
	//struct ether_header *eh = (struct ether_header *) sendbuf;
	//struct iphdr *iph = (struct iphdr *) (sendbuf + sizeof(struct ether_header));
	struct sockaddr_ll socket_address;
	char ifName[IFNAMSIZ];
	//struct gfast_mngm_hdr gfast_hdr;
	struct my_packet pkt;
	char buf[1024];
	struct sockaddr_ll client;
	socklen_t clientsz;

	/* Get interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, CT_IF);

	/* Open RAW socket to send on */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
	    perror("socket");
	}

	/* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
		perror("SIOCGIFINDEX");
		return -1;
	}

	/* Get the MAC address of the interface to send on */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0) {
		perror("SIOCGIFHWADDR");
		return -1;
	}

	memset(&pkt, 0, sizeof(pkt));
	memcpy(pkt.eh.ether_shost, if_mac.ifr_hwaddr.sa_data, sizeof(pkt.eh.ether_shost));
	memcpy(pkt.eh.ether_dhost, bcastmac, sizeof(pkt.eh.ether_dhost));
	pkt.eh.ether_type = htons(GFASTTYPE);

	pkt.gh.opcode = gfast_opcode_memread;
	pkt.gh.seqNum = GFAST_SN_DISCOVERY;
	pkt.gh.len = DFE_DISC_READMEM_LEN;
	pkt.gh.opAddr = GFAST_DFE_MEMADDR_CHIP_INFO;
#if 0
	/* Construct the Ethernet header */
	memset(sendbuf, 0, BUF_SIZ);
	/* Ethernet header */

	eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
	eh->ether_dhost[0] = bcastmac[0];
	eh->ether_dhost[1] = bcastmac[1];
	eh->ether_dhost[2] = bcastmac[2];
	eh->ether_dhost[3] = bcastmac[3];
	eh->ether_dhost[4] = bcastmac[4];
	eh->ether_dhost[5] = bcastmac[5];
	/* Ethertype field */
	eh->ether_type = htons(GFASTTYPE);
	tx_len += sizeof(struct ether_header);

	gfast_hdr.opcode = gfast_opcode_memread;
	gfast_hdr.seqNum = GFAST_SN_DISCOVERY;
	gfast_hdr.len = DFE_DISC_READMEM_LEN;
	gfast_hdr.opAddr = GFAST_DFE_MEMADDR_CHIP_INFO;
	memcpy(&sendbuf[tx_len], &gfast_hdr, sizeof(gfast_hdr));
	tx_len += sizeof(gfast_hdr);
#endif

	//write(1, &pkt, sizeof(pkt));
	/* Packet data */
	memset(&socket_address, 0, sizeof(socket_address));
	socket_address.sll_protocol = htons(ETH_P_ALL);
	/* Index of the network device */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	/* Address length*/
	socket_address.sll_halen = ETH_ALEN;
	/* Destination MAC */
	socket_address.sll_addr[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	socket_address.sll_addr[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	socket_address.sll_addr[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	socket_address.sll_addr[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	socket_address.sll_addr[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	socket_address.sll_addr[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];


	printf("%x %x %02x:%02x:%02x:%02x:%02x:%02x\n", socket_address.sll_ifindex,
		socket_address.sll_protocol, 
		socket_address.sll_addr[0],
		socket_address.sll_addr[1],
		socket_address.sll_addr[2],
		socket_address.sll_addr[3],
		socket_address.sll_addr[4],
		socket_address.sll_addr[5]);

	if (bind(sockfd, (struct sockaddr*) &socket_address, sizeof(struct sockaddr_ll))) {
		perror("bind");
		return -1;
	}
	/* Send packet */
	//if (sendto(sockfd, &pkt, sizeof(pkt), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0) {
	//	printf("Send failed\n");
	//	return -1;
	//}

	if (recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr*)&client, &clientsz) < 0) {
		printf("Recv failed\n");
		return -1;
	}

	return 0;
}
