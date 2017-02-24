#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int main()
{
	/* The intention of this program is to do something like:
	 *     _____________     __________________
	 *    |             |   |                  |
	 * -> | nc -lu 1053 |-> | nc -u 8.8.8.8 53 | ->
	 * |  |_____________|   |__________________|   |
	 *  -------------------------------------------
	 * These are two programs, one listening on local UDP port 1053,
	 * the second one connected to public google DNS server.
	 */
	int pipefds[2], pipefds2[2];
	pid_t cpid;

	pipe(pipefds);
	pipe(pipefds2);
	cpid = fork();
	
	switch (cpid) {
	case -1:
		perror("fork");
		exit(-1);
		break;
	case 0: /* In the child */
		dup2(pipefds[1], STDOUT_FILENO);
		dup2(pipefds2[0], STDIN_FILENO);
		char * const args[] = {"nc", "-lu", "1053", NULL};
		execvp("nc", args);
		break;
	default:
		dup2(pipefds[0], STDIN_FILENO);
		dup2(pipefds2[1], STDOUT_FILENO);
		char * const args2[] = {"nc", "-u", "8.8.8.8", "53", NULL};
		execvp("nc", args2);
		break;
	}
	return 0;
}
