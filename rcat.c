#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/select.h>

char bcastmac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

#define CT_IF "ct0.4094"

#define MY_ETHERTYPE 0x22e3
#define SEQNUM_DISCOVERY 1
#define LEN_DISCOVERY 64
#define MEMADDR 0xE1000000
#define memread_opcode 3
#define FRAME_MIN_LEN  (ETH_ZLEN - ETH_HLEN)

struct my_header {
	uint16_t opcode;
	uint16_t len;
	uint16_t seqNum;
	uint8_t  spare1;
	uint8_t  spare2;

	uint32_t opAddr;
} __attribute__((packed));

struct my_packet {
	struct ether_header eh;
	struct my_header gh;
	char spare[FRAME_MIN_LEN - sizeof(struct my_header)];
	char data[0];
};

int rawconnect(int sockfd, const char *ifname, struct my_packet *pkt_out, struct sockaddr_ll *dest_out);

void rwloop(int sockfd, const char *ifname)
{
	char buf[1024];
	int nread, nwritten;
	struct sockaddr_ll dest;
	struct sockaddr_ll client;
	socklen_t clientsz;
	fd_set master_readfds, readfds, writefds;
	int nready;
	struct timeval tout = {
		.tv_sec = 5,
		.tv_usec = 0
	};

	FD_ZERO(&master_readfds);
	FD_ZERO(&readfds);
	FD_ZERO(&writefds);

	FD_SET(STDIN_FILENO, &master_readfds);
	FD_SET(sockfd, &master_readfds);

	rawconnect(sockfd, ifname, NULL, &dest);

	for (;;) {
		readfds = master_readfds;
		nready = select(10, &readfds, &writefds, NULL, &tout);
		if (nready < 0) {
			perror("select");
			return;
		}

		if (FD_ISSET(STDIN_FILENO, &readfds)) {
			nread = read(STDIN_FILENO, buf, sizeof(buf));
			if (nread < 0) {
				perror("read(STDIN_FILENO)");
				break;
			}
			FD_SET(sockfd, &writefds);
		}

		if (FD_ISSET(sockfd, &readfds)) {
			nread = recvfrom(sockfd, buf, sizeof(buf), 0,
				(struct sockaddr *) &client, &clientsz);
			if (nread < 0) {
				perror("recvfrom(sockfd)");
				break;
			}
			FD_SET(STDOUT_FILENO, &writefds);
		}

		if (FD_ISSET(STDOUT_FILENO, &writefds)) {
			nwritten = write(STDOUT_FILENO, buf, nread);
			if (nwritten < 0) {
				perror("write(STDOUT_FILENO)");
				break;
			}
			FD_CLR(STDOUT_FILENO, &writefds);
		}

		if (FD_ISSET(sockfd, &writefds)) {
			nwritten = sendto(sockfd, buf, nread, 0,
				(struct sockaddr *) &dest, sizeof(dest));
			if (nwritten < 0) {
				perror("sendto(sockfd)");
				break;
			}
			FD_CLR(sockfd, &writefds);
		}
	}
}

int Tflag = ETH_P_IP;

int rawconnect(int sockfd, const char *ifname, struct my_packet *pkt_out, struct sockaddr_ll *dest_out)
{
	struct ifreq if_mac, if_idx;
	struct my_packet pkt;
	struct sockaddr_ll dest;

	/* Get the MAC address of the interface to send on */
	//fprintf(stderr, "rawconnect to %s\n", ifname);
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifname, strlen(ifname));
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0) {
		perror("SIOCGIFHWADDR");
		return -1;
	}
	/* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifname, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
		perror("SIOCGIFINDEX");
		return -1;
	}

	memset(&pkt, 0, sizeof(pkt));
	memcpy(&pkt.eh.ether_shost[0], if_mac.ifr_hwaddr.sa_data, sizeof(pkt.eh.ether_shost));
	memcpy(&pkt.eh.ether_dhost[0], bcastmac, sizeof(pkt.eh.ether_dhost));
	pkt.eh.ether_type = htons(Tflag);

	pkt.gh.opcode = memread_opcode;
	pkt.gh.seqNum = SEQNUM_DISCOVERY;
	pkt.gh.len = LEN_DISCOVERY;
	pkt.gh.opAddr = MEMADDR;

	if (pkt_out)
		*pkt_out = pkt;

	memset(&dest, 0, sizeof(dest));
	dest.sll_family = AF_PACKET;
	dest.sll_protocol = htons(Tflag);
	/* Index of the network device */
	dest.sll_ifindex = if_idx.ifr_ifindex;
	/* Address length*/
	dest.sll_halen = ETH_ALEN;
	/* Destination MAC */
	dest.sll_addr[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	dest.sll_addr[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	dest.sll_addr[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	dest.sll_addr[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	dest.sll_addr[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	dest.sll_addr[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];

	if (dest_out)
		*dest_out = dest;

	return sizeof(pkt);
}

int rawbind(int sockfd, const char *ifname)
{
	struct ifreq if_idx;
	struct sockaddr_ll socket_address;

	printf("binding to %s\n", ifname);
	/* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifname, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
		perror("SIOCGIFINDEX");
		return -1;
	}

	memset(&socket_address, 0, sizeof(socket_address));
	socket_address.sll_family = AF_PACKET;
	socket_address.sll_protocol = htons(Tflag);
	/* Index of the network device */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;

	if (bind(sockfd, (struct sockaddr*) &socket_address, sizeof(struct sockaddr_ll))) {
		perror("bind");
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int sockfd;
	int c;
	const char *iflag = NULL;
	int dflag = 0, tflag = 0, lflag = 0;
	char dpacket[1024];
	static struct option long_options[] = {
		{"listen",        no_argument,       0, 'l'},
		{"disc-packet",   no_argument,       0, 'd'},
		{"interface",     required_argument, 0, 'i'},
		{"ethertype",     required_argument, 0, 't'},
		{0,               0,                 0,  0 }
	};

	for (;;) {
		c = getopt_long(argc, argv, "ldi:t:",
			long_options, NULL);

		if (c == -1)
			break;

		switch (c) {
		case 'l':
			lflag = 1;
			break;
		case 'd':
			dflag = 1;
			break;
		case 'i':
			iflag = optarg;
			break;
		case 't':
			tflag = atoi(optarg);
			Tflag = tflag;
			break;
		}
	}

	/* Open RAW socket to send on */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
	    perror("socket");
	}

	if (!iflag) {
		fprintf(stderr, "no interface specified\n");
		return -1;
	}

	if (dflag) {
		fprintf(stderr, "in discovery packet mode\n");
		int dpacketsz;
		memset(dpacket, 0, sizeof(dpacket));
		dpacketsz = rawconnect(sockfd, iflag, (struct my_packet *) dpacket, NULL);
		write(1, dpacket, dpacketsz);
		return 0;
	}

	if (lflag) {
		fprintf(stderr, "in listen mode\n");
		rawbind(sockfd, iflag);
		rwloop(sockfd, iflag);
		return 0;
	}

	fprintf(stderr, "in write mode\n");
	rwloop(sockfd, iflag);

	return 0;
}
