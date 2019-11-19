/*
 * socket-client.c
 * Simple TCP/IP communication using sockets
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 */

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "socket-common.h"
/* Insist until all of the data has been written */
ssize_t insist_write(int fd, const void *buf, size_t cnt)
{
	ssize_t ret;
	size_t orig_cnt = cnt;
	
	while (cnt > 0) {
	        ret = write(fd, buf, cnt);
	        if (ret < 0)
	                return ret;
	        buf += ret;
	        cnt -= ret;
	}

	return orig_cnt;
}

static int running;

static void handler (int signum) 
{
	running=0;
}


int main(int argc, char *argv[])
{
	struct sigaction sigact;
	running=1;
	sigact.sa_handler=handler;
	sigact.sa_flags=SA_RESTART;
	sigaction(SIGINT,&sigact,NULL);
	int sd, port;
	ssize_t n;
	char buf[buff_size];
	char *hostname;
	struct hostent *hp;
	struct sockaddr_in sa;
	fd_set rfds;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s hostname port\n", argv[0]);
		exit(1);
	}
	hostname = argv[1];
	port = atoi(argv[2]); /* Needs better error checking */

	/* Create TCP/IP socket, used as main chat channel */
	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	fprintf(stderr, "Created TCP socket\n");
	
	/* Look up remote hostname on DNS */
	if ( !(hp = gethostbyname(hostname))) {
		printf("DNS lookup failed for host %s\n", hostname);
		exit(1);
	}

	/* Connect to remote TCP port */
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	memcpy(&sa.sin_addr.s_addr, hp->h_addr, sizeof(struct in_addr));
	fprintf(stderr, "Connecting to remote host... "); fflush(stderr);
	if (connect(sd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		perror("connect");
		exit(1);
	}
	fprintf(stderr, "Connected.\n");

	/* Be careful with buffer overruns, ensure NUL-termination */
	/* Say something... */
	FD_ZERO(&rfds);
	FD_SET(0,&rfds);
	FD_SET(sd,&rfds);
	
	while(running) {
		FD_ZERO(&rfds);
		FD_SET(0,&rfds);
		FD_SET(sd,&rfds);
		if (select(sd+1,&rfds,NULL,NULL,NULL)< 0) {
			if(errno==EINTR) {
				printf("\n Interrupted by Signal. Terminating connection... \n");
				continue;
			}
			else
			perror("select");
			exit(1);
		}
		if (FD_ISSET(0,&rfds)) {
			n = read(0, buf, sizeof(buf)-1);
			
			if (n < 0) {
				perror("read");
				exit(1);
			}
			buf[n]='\0';
			if (insist_write(sd, buf, n) != n) {
				perror("write");
				exit(1);
			}
			continue;
		}
		if (FD_ISSET(sd,&rfds)) {
			n = read(sd, buf, sizeof(buf)-1);
			if (n < 0) {
				perror("read");
				exit(1);
			}
			buf[n]='\0';
			if (insist_write(1, buf, n) != n) {
				perror("write");
				exit(1);
			}
			continue;
		}
	}
	/*
	 * Let the remote know we're not going to write anything else.
	 * Try removing the shutdown() call and see what happens.
	 */
	printf("Program shutting down due to Ctrl+C\n");
	if (shutdown(sd, SHUT_WR) < 0) {
		perror("shutdown");
		exit(1);
	}
	return 0;
}
