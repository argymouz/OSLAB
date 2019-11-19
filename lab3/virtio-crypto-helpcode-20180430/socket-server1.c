/*
 * socket-server.c
 * Simple TCP/IP communication using sockets
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 */
#define MAX_CONN 3
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <time.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "socket-common.h"

/* Convert a buffer to upercase */
void toupper_buf(char *buf, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		buf[i] = toupper(buf[i]);
}

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

int main(void)
{
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);

	fd_set rfds;
	int nfds,nconn,i,j;
	char buf[buff_size];
	char bufout[buff_size];
	char addrstr[INET_ADDRSTRLEN];
	int sd, newsd;
	int conns[MAX_CONN];
	ssize_t n;
	socklen_t len;
	struct sockaddr_in sa;
	len = sizeof(struct sockaddr_in);

	/* Make sure a broken connection doesn't kill us */
	signal(SIGPIPE, SIG_IGN);

	/* Create TCP/IP socket, used as main chat channel */
	if ((sd = socket(PF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	fprintf(stderr, "Created TCP socket\n");

	/* Bind to a well-known port */
	memset(&sa, 0, sizeof(sa));
	memset(&conns, 0, sizeof(conns));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(TCP_PORT);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("bind");
		exit(1);
	}
	fprintf(stderr, "Bound TCP socket to port %d\n", TCP_PORT);

	/* Listen for incoming connections */
	if (listen(sd, TCP_BACKLOG) < 0) {
		perror("listen");
		exit(1);
	}
	FD_ZERO(&rfds);
	nfds=sd+1;
	FD_SET(sd,&rfds);
	nconn=MAX_CONN;
	/* Loop forever, accept()ing connections */
	fprintf(stderr, "Waiting for an incoming connection...\n");
	while(1) {
		nfds=sd+1;
		FD_ZERO(&rfds);
		//remake fdset
		FD_SET(sd,&rfds);
		for(i=0;i<nconn;i++){
			if (conns[i]==0) continue;
			else FD_SET(conns[i],&rfds);
			if (nfds<(conns[i]+1)) nfds=conns[i]+1;
		}
		if (select(nfds,&rfds,NULL,NULL,NULL)==-1) {
			if (errno==EBADF) printf("Its a bad f d \n");
			perror("select");
			exit(1);
		}		
		if (FD_ISSET(sd,&rfds)) {
		/* Accept an incoming connection */
			if ((newsd = accept(sd, (struct sockaddr *)&sa, &len)) < 0) {
				if ((errno==EAGAIN)||(errno==EWOULDBLOCK)) continue;
				perror("accept");
				exit(1);
			}
			bzero(&sa,len);
			if (getpeername(newsd,(struct sockaddr *)&sa, &len)<0) {
				perror("getpeername");
				exit(1);
			}
			if (!inet_ntop(AF_INET, &sa.sin_addr, addrstr, sizeof(addrstr))) {
				perror("could not format IP address");
				exit(1);
			}
			for(i=0;i<nconn;i++) {
				if (conns[i]==0) {conns[i]=newsd;break;}
			}
			if (i==nconn) { 
			//too many connections, you cant connect now
				strncpy(bufout,"Too many connected clients right now. Try again later.\n",sizeof(bufout)-1);
				bufout[sizeof(bufout)-1]='\0';
				n=strlen(bufout);
				if (insist_write(newsd, bufout, n) != n) {
					perror("write to remote peer failed");
					exit(1);
				}
				continue;
			}
			FD_SET(newsd,&rfds);
			if (newsd+1>nfds) nfds=newsd+1;
			t = time(NULL);
			tm = *localtime(&t);
			n=sprintf(bufout, "[%d-%d-%d]User from [%s:%d] has joined the chat.\n",tm.tm_hour,tm.tm_min,tm.tm_sec,addrstr, ntohs(sa.sin_port));
			for(i=0;i<nconn;i++) {
				if(conns[i]==0) continue;
				newsd=conns[i];
				if (insist_write(newsd, bufout, n) != n) {
					perror("write to remote peer failed");
					exit(1);
				}
			}
			continue;
		}
		for (i=0;i<nconn;i++) {
			if (conns[i]==0) continue;
			newsd=conns[i];
			if (!FD_ISSET(newsd,&rfds)) continue;
			n = read(newsd, buf, sizeof(buf));
			if (n <= 0) {
				if (n < 0)
					perror("read from remote peer failed");
				else
				//	fprintf(stderr, "Peer went away\n");
					bzero(&sa,len);
					if (getpeername(newsd,(struct sockaddr *)&sa, &len)<0) {
						perror("getpeername");
						exit(1);
					}

					if (!inet_ntop(AF_INET, &sa.sin_addr, addrstr, sizeof(addrstr))) {
						perror("could not format IP address");
						exit(1);
					}
					t = time(NULL);
					tm = *localtime(&t);
					n=sprintf(bufout, "[%d-%d-%d]User from [%s:%d] has left the chat.\n",tm.tm_hour,tm.tm_min,tm.tm_sec,addrstr, ntohs(sa.sin_port));			
					for(j=0;j<nconn;j++) {
						if (conns[j]==0) continue;						
						newsd=conns[j];
						if (insist_write(newsd, bufout, n) != n) {
							perror("write to remote peer failed");
							exit(1);
						}
					}
					newsd=conns[i];
					conns[i]=0;
					FD_CLR(newsd,&rfds);
					if (close(newsd) < 0)
						perror("close");
					newsd=-1;
					break;
			}
			buf[n]='\0';	
			bzero(&sa,len);
			if (getpeername(newsd,(struct sockaddr *)&sa, &len)<0) {
				perror("getpeername");
				exit(1);
			}
			if (!inet_ntop(AF_INET, &sa.sin_addr, addrstr, sizeof(addrstr))) {
				perror("could not format IP address");
				exit(1);
			}
			t = time(NULL);
			tm = *localtime(&t);
			n=sprintf(bufout, "[%d-%d-%d][%s:%d] said: %s",tm.tm_hour,tm.tm_min,tm.tm_sec,addrstr, ntohs(sa.sin_port),buf);
			for(j=0;j<nconn;j++) {
				if (conns[j]==0) continue;
				newsd=conns[j];
				if (insist_write(newsd, bufout, n) != n) {
					perror("write to remote peer failed");
					exit(1);
				}
			}
			break;
		}
	}

	/* This will never happen */
	return 1;
}

