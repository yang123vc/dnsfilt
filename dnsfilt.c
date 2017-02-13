#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>

struct DNS_HEADER
{
	unsigned short id; /* identification number */

	unsigned char rd :1; /* recursion desired */
	unsigned char tc :1; /* truncated message */
	unsigned char aa :1; /* authoritive answer */
	unsigned char opcode :4; /* purpose of message */
	unsigned char qr :1; /* query/response flag */

	unsigned char rcode :4; /* response code */
	unsigned char cd :1; /* checking disabled */
	unsigned char ad :1; /* authenticated data */
	unsigned char z :1; /* its z! reserved */
	unsigned char ra :1; /* recursion available */

	unsigned short q_count; /* number of question entries */
	unsigned short ans_count; /* number of answer entries */
	unsigned short auth_count; /* number of authority entries */
	unsigned short add_count; /* number of resource entries */
};

static char blacklist[100][255];
static size_t nr_blacklisted;

void die(const char *msg)
{
	perror(msg);
	exit(-1);
}

static int name_blacklisted(const char *name)
{
	size_t i;

	for (i = 0; i < nr_blacklisted; i++)
		if (strstr(name, blacklist[i]))
			return 1;

	return 0;
}

const char *extract_hostname(const struct DNS_HEADER *h)
{
	static char hostname[255];
	const char *p;
	int nr_chars;
	int i;

	p = (const char *)++h;
	i = 0;
	while ((nr_chars = p[i]) != 0) {
		hostname[i] = '.';
		i++;
		strncpy(&hostname[i], &p[i], nr_chars);
		i += nr_chars;
	}
	hostname[i] = 0;

	return hostname;
}

static int read_blacklist_entry(const char *line)
{
	int n;

	n = sscanf(line, "-b=%s", &blacklist[nr_blacklisted][0]);

	if (!n)
		return 1;

	nr_blacklisted++;
	return 0;
}

void header_set_refused(struct DNS_HEADER *h)
{
	h->rcode = 5;
}

static void read_blacklist(int argc, char *argv[])
{
	int i;
	
	for (i = 1; i < argc; i++) {
		read_blacklist_entry(argv[i]);
	}
}

static void print_blacklist()
{
	int i;
	
	for (i=0; i < nr_blacklisted; i++)
		puts(blacklist[i]);
}

static int udp_incoming_sock(short port)
{
	int sockfd;
	int optval = 1;
	struct sockaddr_in si; /* server's addr */

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) 
		die("dnsp_udp_incoming_sock: error opening socket");

	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
		(const void *)&optval , sizeof(int));

	memset(&si, 0, sizeof(si));
	si.sin_family = AF_INET;
	si.sin_addr.s_addr = htonl(INADDR_ANY);
	si.sin_port = htons((unsigned short)port);

	if (bind(sockfd, (struct sockaddr *) &si, sizeof(si)) < 0) 
		die("dnsp_udp_incoming_sock: error on binding");

	return sockfd;
}

static void input_loop(short port)
{
	int netfd;
	char netin_buf[1024];
	char stdin_buf[1024];
	struct sockaddr_in client;
	socklen_t client_len = sizeof(client);
	int netin_nrecvd;
	int stdin_nrecvd;
	fd_set readfds, writefds;
	int nready;

	netfd = udp_incoming_sock(port);
	FD_ZERO(&writefds);

	for (;;) {
		FD_ZERO(&readfds);

		FD_SET(netfd, &readfds);
		FD_SET(STDIN_FILENO, &readfds);

		nready = select(10, &readfds, &writefds, 0, 0);

		if (FD_ISSET(STDOUT_FILENO, &writefds)) {
			/* write to netfd */
			write(STDOUT_FILENO, netin_buf, netin_nrecvd);
			/* remove self from polling */
			FD_CLR(STDOUT_FILENO, &writefds);
		}

		if (FD_ISSET(netfd, &writefds)) {
			/* write to netfd */
			sendto(netfd, stdin_buf, stdin_nrecvd, 0,
				(struct sockaddr *)&client, client_len);
			FD_CLR(netfd, &writefds);
		}

		if (FD_ISSET(STDIN_FILENO, &readfds)) {
			/* Read from stdin */
			stdin_nrecvd = read(STDIN_FILENO, stdin_buf,
				sizeof(stdin_buf));
			FD_SET(netfd, &writefds);
		}

		if (FD_ISSET(netfd, &readfds)) {
			/* Read from netfd */
			netin_nrecvd = recvfrom(netfd, netin_buf,
				sizeof(netin_buf), 0,
				(struct sockaddr *)&client, &client_len);
			FD_SET(STDOUT_FILENO, &writefds);
		}

	}

}

static int udp_upstream_sock()
{
	int sockfd;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) 
		die("udp_upstream_sock: error opening socket");

	return sockfd;
}

static const char *get_upstream_address()
{
	return "8.8.8.8";
}

static void make_upstream_sockaddr(struct sockaddr_in *outaddr)
{
	struct sockaddr_in si;

	memset(&si, 0, sizeof(si));
	si.sin_family = AF_INET;
	si.sin_addr.s_addr = inet_addr(get_upstream_address());
	si.sin_port = htons((unsigned short)53);

	*outaddr = si;
}

static void output_loop()
{
	int netfd;
	char netin_buf[1024];
	char stdin_buf[1024];
	struct sockaddr_in upstream;
	socklen_t upstream_len = sizeof(upstream);
	int netin_nrecvd;
	int stdin_nrecvd;
	fd_set readfds, writefds;
	int nready;

	netfd = udp_upstream_sock();
	make_upstream_sockaddr(&upstream);

	FD_ZERO(&writefds);

	for (;;) {
		FD_ZERO(&readfds);

		FD_SET(netfd, &readfds);
		FD_SET(STDIN_FILENO, &readfds);

		nready = select(10, &readfds, &writefds, 0, 0);

		if (FD_ISSET(STDOUT_FILENO, &writefds)) {
			/* write to netfd */
			write(STDOUT_FILENO, netin_buf, netin_nrecvd);
			/* remove self from polling */
			FD_CLR(STDOUT_FILENO, &writefds);
		}

		if (FD_ISSET(netfd, &writefds)) {
			/* write to netfd */
			sendto(netfd, stdin_buf, stdin_nrecvd, 0,
				(struct sockaddr *)&upstream, upstream_len);
			FD_CLR(netfd, &writefds);
		}

		if (FD_ISSET(STDIN_FILENO, &readfds)) {
			/* Read from stdin */
			stdin_nrecvd = read(STDIN_FILENO, stdin_buf,
				sizeof(stdin_buf));
			FD_SET(netfd, &writefds);
		}

		if (FD_ISSET(netfd, &readfds)) {
			/* Read from netfd */
			netin_nrecvd = recvfrom(netfd, netin_buf,
				sizeof(netin_buf), 0, 0, 0);
			FD_SET(STDOUT_FILENO, &writefds);
		}

	}
}

int main(int argc, char *argv[])
{
	if (argc < 2)
		die("Not enough args");

	if (!strcmp(argv[1], "-l"))
		input_loop(53);
	else if (!strcmp(argv[1], "-u"))
		output_loop();

	return 0;
}
