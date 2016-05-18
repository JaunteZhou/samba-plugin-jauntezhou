#ifndef _KEY_HEAD

#define _KEY_HEAD


#include <stdlib.h>
#include <sys/types.h>
#include <stdio.h>
#include <sys/socket.h>
#include <string.h>

#include <inttypes.h>

#define KEY_REQ_TYPE 	1
#define KEY_REQ_MAX 	1 + 8 + 8 + 8

#define KEY_RES_TYPE 	2
#define RES_BUF_MAX 	256
#define KEY_RES_MAX 	1 + 1 + RES_BUF_MAX

#define KEY_SIZE 	16
#define EN_KEY_SIZE 	128

#define SERVER_PORT	0x8888
#define SERVER_IP	"127.0.0.1"

//RSA encrypt and decrypt
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<openssl/err.h>
#define RSA_PRIVATE_KEY 	"/home/jauntezhou/Documents/samba-4.4.0/source3/smbd/prikey.pem"
#define RSA_PUBLIC_KEY		"/home/jauntezhou/Documents/samba_key_server/pubkey.pem"

typedef struct KEY_REQUEST{
	uint8_t type;
	uint64_t devid;
	uint64_t inode;
	uint64_t extid;
}KeyReq_T;

typedef struct KEY_RESPONSE{
	uint8_t type;
	uint8_t buf_len;
	unsigned char buf[RES_BUF_MAX];
}KeyRes_T;

#endif
