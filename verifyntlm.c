/*

php ntlm authentication library
Version 1.2
verifyntlm.c - verifies NTLM credentials against samba using pdbedit

Copyright (c) 2009-2010 Loune Lam

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.


Prerequisites:
- pdbedit (samba) - user database must be store locally
- libssl (openssl)


To install, compile and set the sticky bit:
# gcc verifyntlm.c -lssl -o verifyntlm
# chown root verifyntlm
# chmod u=rwxs,g=x,o=x verifyntlm

Move the binary to a location such as /sbin/
# mv verifyntlm /sbin

If you put the binary somewhere else, please modify $ntlm_verifyntlmpath in ntlm.php

For more, see http://siphon9.net/loune/2010/12/php-ntlm-integration-with-samba/


*/

#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <iconv.h>

#define PDBEDIT_PATH "/usr/bin/pdbedit"

int get_hash_from_str(char* line, char* buf, int bufsize) {
	int colons = 0;
	char *capture = 0;
	char *c = line;
	int count = 0;
	int targetcolon = 3;

	for (; *c != 0; c++) {
		if (*c == ':') {
			colons++;
			if (colons == targetcolon + 1)
				goto done;
			if (colons == targetcolon) {
				capture = c+1;
				continue;
			}
		}

		if (capture != 0) {
			if (bufsize == count + 1)
				goto done;
			buf[c-capture] = *c;
			count++;
		}

	}

done:
	buf[count] = '\0';
	return count;
}

int get_ntlm_hash(char* user, size_t userlen, char *buffer, size_t buflen) {
	char str[512];
	int pipefd[2];
	pid_t pid;
	int status, died;
	
	pipe (pipefd);

	switch (pid = fork()) {
		case -1:
			printf("Error: can't fork\n");
			exit(-1);

		case 0: /* child */
			close(STDOUT_FILENO);
			close(STDERR_FILENO);

			dup2(pipefd[1], STDOUT_FILENO);
			dup2(pipefd[1], STDERR_FILENO);

			close (pipefd[0]);
			setuid(0);
			execl(PDBEDIT_PATH, "pdbedit", "-w", user, NULL);

		default: /* parent */
			close(STDIN_FILENO);
			dup2(pipefd[0], STDIN_FILENO);
			close(pipefd[1]);
			while (fgets(str, sizeof(str), stdin)) {
				char *c;

				int len = strlen(str);
				if (userlen < len)
					len = userlen;

				for (c = str; c < str + len; c++)
					*c = toupper(*c);

				if (len && !strncmp(str, user, len)) {
					/* found our match */
					get_hash_from_str(str, buffer, buflen);
					return 0;
				}
			}

			died = wait(&status);
	}

	return 1;
}


int hex_decode(const char* input, char* buffer, unsigned int max_buf_len) {
	const char *c = input;
	char *b = buffer;
	unsigned char mult = 16;

	if (max_buf_len == 0)
		return 0;

	*b = 0;
	while (1) {
		if (*c >= 'A' && *c <= 'F')
			*b += (*c - 'A' + 10) * mult;
		else if (*c >= 'a' && *c <= 'f')
			*b += (*c - 'a' + 10) * mult;
		else if (*c >= '0' && *c <= '9')
			*b += (*c - '0') * mult;
		else
			break;

		if (mult == 16) {
			mult = 1;
		}
		else {
			mult = 16;
			b++;
			if ((unsigned int)(b - (char *)buffer) == max_buf_len)
				break;
			*b = 0;
		}

		c++;
	}

	if (mult == 1) b++; /* allow partial match */

	return b - (char *)buffer;
}

int main(int argc, char** argv) {

	if (geteuid() != 0) {
		printf("SUID root needed. Please set the sticky bit and correct permissions for %s.\n"
				"    ie:\n"
				"    # chown root %s\n"
				"    # chmod u=rwxs,g=x,o=x %s\n", argv[0], argv[0], argv[0]);
		exit(-1);
	}

	if (access(PDBEDIT_PATH, F_OK ) == -1) {
		printf("%s not found. Please install samba or change the PDBEDIT_PATH constant.\n", PDBEDIT_PATH);
		exit(-1);
	}

	if (argc < 7) {
		printf("usage: %s challenge user domain workstation clientblob clientblobhash\n", argv[0]);
		printf("string arguments are expected to be in UTF16LE\n");
		printf("all arguments are hex encoded\n");
		printf("prints 1 if successful, otherwise 0\n");
		exit(-1);
	}


	char *challenge = (char *)malloc(strlen(argv[1]));
	size_t challenge_len = hex_decode(argv[1], challenge, strlen(argv[1]));
	char *user = (char *)malloc(strlen(argv[2]));
	size_t user_len = hex_decode(argv[2], user, strlen(argv[2]));
	char *domain = (char *)malloc(strlen(argv[3]));
	size_t domain_len = hex_decode(argv[3], domain, strlen(argv[3]));
	char *workstation = (char *)malloc(strlen(argv[4]));
	size_t workstation_len = hex_decode(argv[4], workstation, strlen(argv[4]));
	char *clientblobhash = (char *)malloc(strlen(argv[5]));
	size_t clientblobhash_len = hex_decode(argv[5], clientblobhash, strlen(argv[5]));
	char *clientblob = (char *)malloc(strlen(argv[6]));
	size_t clientblob_len = hex_decode(argv[6], clientblob, strlen(argv[6]));

	/* convert username from UTF-16LE to UTF-8 */
	char userutf8[512];
	char* conv_user = user;
	size_t conv_user_len = user_len;
	char* conv_userutf8 = userutf8;
	size_t conv_userutf8_len = sizeof(userutf8) - 1;
	iconv_t converter = iconv_open("UTF-8", "UTF-16LE");
	iconv(converter, &conv_user, &conv_user_len, &conv_userutf8, &conv_userutf8_len);
	*conv_userutf8 = 0;
	iconv_close(converter);

	/* find hash */
	char buffer[512];
	if (!get_ntlm_hash(userutf8, conv_userutf8 - userutf8, buffer, sizeof(buffer))) {
		char decoded[512];
		int decoded_len = hex_decode(buffer, decoded, sizeof(decoded));

		int userdomain_len = user_len + domain_len;
		unsigned char* userdomain = (unsigned char *)malloc(userdomain_len);
		memcpy(userdomain, user, user_len);
		memcpy(userdomain + user_len, domain, domain_len);

		unsigned char ntlmv2hash[EVP_MAX_MD_SIZE];
		unsigned int ntlmv2hash_len = 0;
		HMAC(EVP_md5(), decoded, decoded_len, userdomain, userdomain_len, ntlmv2hash, &ntlmv2hash_len);

		int challengeclientblob_len = challenge_len + clientblob_len;
		unsigned char* challengeclientblob = (unsigned char *)malloc(challengeclientblob_len);
		memcpy(challengeclientblob, challenge, challenge_len);
		memcpy(challengeclientblob + challenge_len, clientblob, clientblob_len);

		unsigned char blobhash[EVP_MAX_MD_SIZE];
		unsigned int blobhash_len = 0;
		HMAC(EVP_md5(), ntlmv2hash, ntlmv2hash_len, challengeclientblob,
			challengeclientblob_len, blobhash, &blobhash_len);

		if ((unsigned int)clientblobhash_len == blobhash_len 
			&& !strncmp(clientblobhash, (char *)blobhash, blobhash_len))
			printf("1\n");
		else
			printf("0\n");

	}
	else {
		printf("0\n");
	}

	return 0;
}

