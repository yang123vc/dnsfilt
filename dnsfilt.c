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
#include <getopt.h>

#if 0
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
#endif
void die(const char *msg)
{
	perror(msg);
	exit(-1);
}
static int vflag;
static int udpsock();
static void make_listen_sockaddr(struct sockaddr_in *outaddr, short port);
static void make_upstream_sockaddr(struct sockaddr_in *outaddr,
	const char *host, short port);
static int udp_listen_sock(short port)
{
	int sockfd;
	int optval = 1;
	struct sockaddr_in si; /* server's addr */

	sockfd = udpsock();

	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
		(const void *)&optval , sizeof(int));

	make_listen_sockaddr(&si, port);

	if (bind(sockfd, (struct sockaddr *) &si, sizeof(si)) < 0) 
		die("udp_listen_sock: error on binding");

	return sockfd;
}

static int udp_upstream_sock(const char *host, short port)
{
	int sockfd;
	struct sockaddr_in si;
	socklen_t len = sizeof(si);

	sockfd = udpsock();
	make_upstream_sockaddr(&si, host, port);
	
	if (connect(sockfd, (struct sockaddr *)&si, len) < 0)
		die("udp_upstream_sock: error on connect");

	return sockfd;
}

static int udpsock()
{
	int sockfd;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) 
		die("udpsock: error opening socket");

	return sockfd;
}

static void make_upstream_sockaddr(struct sockaddr_in *outaddr,
	const char *host, short port)
{
	struct sockaddr_in si;

	memset(&si, 0, sizeof(si));
	si.sin_family = AF_INET;
	si.sin_addr.s_addr = inet_addr(host);
	si.sin_port = htons(port);

	*outaddr = si;
}

static void make_listen_sockaddr(struct sockaddr_in *outaddr, short port)
{
	struct sockaddr_in si;

	memset(&si, 0, sizeof(si));
	si.sin_family = AF_INET;
	si.sin_addr.s_addr = htonl(INADDR_ANY);
	si.sin_port = htons(port);

	*outaddr = si;
}

static void connect_to_first_client(int netfd)
{
	int rv;
	char buf[1024];
	struct sockaddr_in si;
	socklen_t len = sizeof(si);

	rv = recvfrom(netfd, buf, sizeof(buf), MSG_PEEK,
		(struct sockaddr *)&si, &len);
	if (rv < 0)
		die("recvfrom");

	rv = connect(netfd, (struct sockaddr *)&si, len);
	if (rv < 0)
		die("connect");
}

static void rwloop(int netfd)
{
	char netin_buf[1024], stdin_buf[1024];
	int netin_nrecvd, stdin_nrecvd;
	int netout_nsent, stdout_nsent;
	fd_set master_readfds, readfds, writefds;
	int nready;

	FD_ZERO(&master_readfds);
	FD_ZERO(&readfds);
	FD_ZERO(&writefds);

	FD_SET(netfd, &master_readfds);
	FD_SET(STDIN_FILENO, &master_readfds);

	for (;;) {
		readfds = master_readfds;

		nready = select(10, &readfds, &writefds, 0, 0);

		if (vflag)
			fprintf(stderr, "nready %d\n", nready);
		if (FD_ISSET(STDOUT_FILENO, &writefds)) {
			/* write to stdout */
			stdout_nsent = write(STDOUT_FILENO, netin_buf, netin_nrecvd);

			if (stdout_nsent < 0)
				die("-1 on write to stdout");
			else
				if (vflag)
					fprintf(stderr, "%d/%d bytes to stdout\n", stdout_nsent, netin_nrecvd);
			/* remove self from polling */
			FD_CLR(STDOUT_FILENO, &writefds);
		}

		if (FD_ISSET(netfd, &writefds)) {
			/* write to netfd */
			netout_nsent = write(netfd, stdin_buf, stdin_nrecvd);
			if (netout_nsent < 0)
				die("-1 on write to netfd");
			else
				if (vflag)
					fprintf(stderr, "%d/%d bytes to netfd\n", netout_nsent, stdin_nrecvd);
			FD_CLR(netfd, &writefds);
		}

		if (FD_ISSET(STDIN_FILENO, &readfds)) {
			/* Read from stdin */
			stdin_nrecvd = read(STDIN_FILENO, stdin_buf,
				sizeof(stdin_buf));
			if (vflag)
				fprintf(stderr, "%d bytes from stdin\n", stdin_nrecvd);
			FD_SET(netfd, &writefds);
		}

		if (FD_ISSET(netfd, &readfds)) {
			/* Read from netfd */
			netin_nrecvd = read(netfd, netin_buf,
				sizeof(netin_buf));
			if (vflag)
				fprintf(stderr, "%d bytes from netfd\n", netin_nrecvd);
			FD_SET(STDOUT_FILENO, &writefds);
		}

	}
}

int main(int argc, char *argv[])
{
	int netfd;
	int opt, opt_idx;
	int lflag = 0;
	const char *hflag = 0, *pflag = 0;
	struct option long_options[] = {
		{"listen",  no_argument,       0, 'l'},
		{"host",    required_argument, 0, 'h'},
		{"port",    required_argument, 0, 'p'},
		{"verbose", no_argument,       0, 'v'}
	};

	for (;;) {
		opt = getopt_long(argc, argv, "lvh:p:", long_options, &opt_idx);
		if (opt < 0)
			break;

		switch (opt) {
		case 'l':
			lflag = 1;
			break;
		case 'h':
			hflag = optarg;
			break;
		case 'p':
			pflag = optarg;
			break;
		case 'v':
			vflag = 1;
			break;
		}
	}

	if (lflag && hflag) {
		fprintf(stderr, "Cannot use --listen and --host\n");
		return -1;
	}

	if (!lflag && !hflag) {
		fprintf(stderr, "Must use --listen or --host\n");
		return -1;
	}

	if (!pflag) {
		fprintf(stderr, "--port required\n");
		return -1;
	}

	if (lflag) {
		netfd = udp_listen_sock(atoi(pflag));
		connect_to_first_client(netfd);
		rwloop(netfd);
	}

	if (hflag) {
		netfd = udp_upstream_sock(hflag, atoi(pflag));
		rwloop(netfd);
	}

	return 0;
}
