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
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include "cryptodev.h"
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "socket-common.h"

#define DATA_SIZE 256
#define BLOCK_SIZE 16
#define KEY_SIZE 16
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
	int i;
	int cfd;
	cfd = open("/dev/cryptodev0", O_RDWR);
	if (cfd<0) {
		perror("open(/dev/cryptodev0)");
		return 1;
	}


	struct session_op sess;
	struct crypt_op cryp;
	struct sigaction sigact;
	struct {
		unsigned char 	plaintext[DATA_SIZE],
				ciphertext[DATA_SIZE],
				iv[BLOCK_SIZE],
				key[KEY_SIZE];
	} data;
	memset(&sess, 0, sizeof(sess));
	memset(&cryp, 0, sizeof(cryp));
	memset(&data.iv,0,sizeof(data.iv));
	memset(&data.key,1,sizeof(data.key));
	sess.cipher = CRYPTO_AES_CBC;
	sess.keylen = KEY_SIZE;
	sess.key = data.key;
	
	if (ioctl(cfd,CIOCGSESSION, &sess)) {
		perror("ioctl(CIOCGSESSION)");
		exit(1);
	}
	
	cryp.ses = sess.ses;
	cryp.iv = data.iv;
	cryp.len = sizeof(data.plaintext);
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
			for(i=0;i<DATA_SIZE;i++){
				if (i<n) data.plaintext[i]=buf[i];
				else data.plaintext[i]='\0';
			}
			cryp.src = data.plaintext;
			cryp.dst = data.ciphertext;
			cryp.op = COP_ENCRYPT;
			if (ioctl(cfd, CIOCCRYPT, &cryp)) {
				perror("ioctl(CIOCCRYPT)");
				exit(1);
			}
	
			if (insist_write(sd, data.ciphertext, DATA_SIZE) != DATA_SIZE) {
				perror("write");
				exit(1);
			}
			continue;
		}
		if (FD_ISSET(sd,&rfds)) {
			n = read(sd, data.ciphertext, DATA_SIZE);
			if (n < 0) {
				perror("read");
				exit(1);
			}
			if (n<DATA_SIZE) continue;
			cryp.src = data.ciphertext;
			cryp.dst = data.plaintext;
			cryp.op = COP_DECRYPT;
			if (ioctl(cfd, CIOCCRYPT, &cryp)) {
				perror("ioctl(CIOCCRYPT)");
				exit(1);
			}	
			for(i=0;i<DATA_SIZE;i++){
				if (data.plaintext[i]!='\0') buf[i]=data.plaintext[i];
				else {buf[i]='\0';break;}
			}
			n=i;
			buf[sizeof(buf)-1]='\0';		
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
	if (ioctl(cfd, CIOCFSESSION, &sess.ses)) {
		perror("ioctl(CIOCFSESSION)");
		exit(1);
	}
	if(close(cfd)<0) {
		perror("close(cfd)");
		exit(1);
	}
	if (shutdown(sd, SHUT_WR) < 0) {
		perror("shutdown");
		exit(1);
	}
	return 0;
}
