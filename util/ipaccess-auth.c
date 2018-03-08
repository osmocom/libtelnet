/* ipaccess nanoBTS proprietary telnet authentication,
 * written by Dieter Spaar <spaar@mirider.augusta.de> */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <openssl/md5.h>

#define CLI_USER "CLICLIENT\n"
#define KEY "Sh1n30nY0uCra2yD1am0nd"

static void compute_response(unsigned char *ubChallenge, unsigned char *ubResponse) 
{
	MD5_CTX md5;
	int i;

	MD5_Init(&md5);

	for(i = 0; i < 4; i++) {
		MD5_Update(&md5, (unsigned char *)KEY, strlen(KEY));
		MD5_Update(&md5, ubChallenge, 16);
	}
	MD5_Final(ubResponse, &md5);
}

// nanoBTS Challenge/Response
void ipaccess_telnet_auth(int sock)
{
	char buffer[512];
	int rs;
        unsigned char  ubResponse[18];
    
        // send client name
        
    	if ((rs = send(sock, CLI_USER, strlen(CLI_USER), 0)) == -1) {
			fprintf(stderr, "send() failed: %s\n", strerror(errno));
			exit(1);
		} else if (rs == 0) {
			fprintf(stderr, "send() unexpectedly returned 0\n");
			exit(1);
		}
		
        // receive challenge

        if ((rs = recv(sock, buffer, sizeof(buffer), 0)) > 0) {
            if(rs != 18 || buffer[0] != '<' || buffer[17] != '>') {
              fprintf(stderr, "unexpected response\n");
              exit(1);
            }
        } else if (rs == 0) {
			fprintf(stderr, "recv(client) unexpectedly returned 0\n");
			exit(1);
        } else {
            fprintf(stderr, "recv(client) failed: %s\n",
                    strerror(errno));
            exit(1);
        }
        
        // calculate response
        
        memset(&ubResponse, 0, sizeof(ubResponse));
  		compute_response(buffer + 1, ubResponse + 1);
        ubResponse[0] = '<';
        ubResponse[17] = '>';
        
        // send response
        if ((rs = send(sock, ubResponse, sizeof(ubResponse), 0)) == -1) {
		fprintf(stderr, "send() failed: %s\n", strerror(errno));
		exit(1);
	} else if (rs == 0) {
		fprintf(stderr, "send() unexpectedly returned 0\n");
		exit(1);
	}        
}
