#ifndef _KEY_HEAD

#define _KEY_HEAD


#include <stdlib.h>
#include <sys/types.h>
#include <stdio.h>
#include <sys/socket.h>
//#include <linux/in.h>
#include <string.h>

#include <inttypes.h>

#define KEY_ROOT 	"/home/jauntezhou/Documents/data/"
#define KEY_ROOT_LEN 	strlen(KEY_ROOT)
#define KEY_SIZE 	16
#define KEY_EN_SIZE 	128

#define KEY_REQ_TYPE 	1
#define FN_MAX 		256
#define UN_MAX 		256
#define REQ_BUF_MAX	FN_MAX+UN_MAX
#define KEY_REQ_MAX 	1+1+1+REQ_BUF_MAX


#define KEY_RES_TYPE 	2
#define RES_BUF_MAX 	256
#define KEY_RES_MAX 	1+1+RES_BUF_MAX

#define SERVER_PORT	0x8889
#define SERVER_IP	"127.0.0.1"

//RSA encrypt and decrypt
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<openssl/err.h>
#define RSA_PRIVATE_KEY 	"prikey.pem"
#define RSA_PUBLIC_KEY		"pubkey.pem"
#define BUFFSIZE 	1024

typedef struct KEY_REQUEST{
	uint8_t type;
	uint8_t un_len;
	uint8_t fn_len;
	char buf[REQ_BUF_MAX];
}KeyReq_T;

typedef struct KEY_RESPONSE{
	uint8_t type;
	uint8_t buf_len;
	unsigned char buf[RES_BUF_MAX];
}KeyRes_T;

#endif
