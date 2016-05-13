/*************************************
文件名： server.c 
linux 下socket网络编程简例  - 服务端程序
服务器端口设为 0x8888   （端口和地址可根据实际情况更改，或者使用参数传入）
服务器地址设为 192.168.1.104
作者:kikilizhm#163.com (将#换为@)
*/

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <inttypes.h>

#include <fcntl.h>

#include "key_head.h"


ssize_t read_key(char *un, char *fn, unsigned char *key)
{
	FILE *fp;
	char *fr;
	//size_t len = 0;
	ssize_t ret;

	fr = (char *)malloc( KEY_ROOT_LEN+strlen(un)+1+strlen(fn) );
	memset( fr, 0, KEY_ROOT_LEN+strlen(un)+1+strlen(fn) );
	strcpy( fr, KEY_ROOT );
	strcpy( fr+KEY_ROOT_LEN, un );
	strcpy( fr+KEY_ROOT_LEN+strlen(un), "_" );
	strcpy( fr+KEY_ROOT_LEN+strlen(un)+1, fn );

	// test //
	printf("user name : %s\n", un);
	printf("file name : %s\n", fn);
	printf( "key save root : %s\n", fr );
	//////////
	ret = access( fr, F_OK );
	if( ret == -1 ){
		fp = fopen( fr, "wb" );
		strncpy( key, "JaunteZhou010502", KEY_SIZE );
		ret = fwrite( key, 1, KEY_SIZE, fp );
		if ( -1 == ret || KEY_SIZE != ret ) {
			printf("Write Key Error !\n");
			return -1;
		}
		fclose(fp);
		return ret;
	}

	fp = fopen(fr, "rb");
	if (fp == NULL)
		return -1;

	ret = fread( key, 1, KEY_SIZE, fp );
	if ( -1 == ret ) {
		printf("Read Key Error !\n");
		return -1;
	} else if ( KEY_SIZE != ret ){
		printf("read length error !\n");
	}
	printf("key : %s\n", key);

	fclose(fp);
	free(fr);
	return ret;
}

ssize_t rsa_encrypt( unsigned char *str, unsigned char *str_en ){
	RSA *p_rsa;
	FILE *fp;
	int str_len,rsa_len;
	ssize_t ret;

	fp = fopen( RSA_PUBLIC_KEY, "r" );
	if( fp == NULL ){
		perror("open key file error");
		return -1;    
	}

	p_rsa = PEM_read_RSA_PUBKEY( fp, NULL, NULL, NULL );
	if( p_rsa == NULL ){
		//if((p_rsa=PEM_read_RSAPublicKey(fp,NULL,NULL,NULL))==NULL){   换成这句死活通不过，无论是否将公钥分离源文件
		ERR_print_errors_fp(stdout);
		return -1;
	}

	str_len = strlen(str);
	rsa_len = RSA_size(p_rsa);

	//str_en = (unsigned char *)malloc(rsa_len+1);
	//memset(p_en,0,rsa_len+1);

	ret = RSA_public_encrypt( rsa_len, str, str_en, p_rsa, RSA_NO_PADDING );
	if( ret < 0 ){
		printf("IN FUNCTION \"rsa_encrypt\" : encrypt str error !!!\n");
		return -1;
	}

	RSA_free(p_rsa);
	fclose(fp);
	return rsa_len;
}

int main()
{
	int sfp,nfp; /* 定义两个描述符 */
	struct sockaddr_in s_add,c_add;
	int sin_size;
	unsigned short portnum = SERVER_PORT; /* 服务端使用端口 */
	ssize_t ret = -1;

	KeyReq_T *req;
	ssize_t req_len;

	char *host_name;
	char *file_name;
	unsigned char *key;

	KeyRes_T *res;
	ssize_t res_len;


	printf("Hello,welcome to my server !\r\n");
	sfp = socket(AF_INET, SOCK_STREAM, 0);
	if( -1 == sfp ){
		printf("socket fail ! \r\n");
		return -1;
	}
	printf("socket ok !\r\n");

	/* 填充服务器端口地址信息，以便下面使用此地址和端口监听 */
	bzero(&s_add,sizeof(struct sockaddr_in));
	s_add.sin_family=AF_INET;
	s_add.sin_addr.s_addr=htonl(INADDR_ANY); /* 这里地址使用全0，即所有 */
	s_add.sin_port=htons(portnum);
	
	/* 使用bind进行绑定端口 */
	ret = bind(sfp,(struct sockaddr *)(&s_add), sizeof(struct sockaddr));
	if( -1 == ret ){
		printf("bind fail !\r\n");
		return -1;
	}
	printf("bind ok !\r\n");
	/* 开始监听相应的端口 */
	ret = listen(sfp,5);
	if( -1 == ret ){
		printf("listen fail !\r\n");
		return -1;
	}
	printf("listen ok\r\n");

	while(1){
		sin_size = sizeof(struct sockaddr_in);

		/* accept阻塞等待用户进行连接 */
		nfp = accept(sfp, (struct sockaddr *)(&c_add), &sin_size);
		
		if( -1 == nfp ){
			printf("accept fail !\r\n");
			return -1;
		}
		printf("accept ok!\r\nServer start get connect from %#x : %#x\r\n",
			ntohl(c_add.sin_addr.s_addr),ntohs(c_add.sin_port));



		req = (KeyReq_T *)malloc(KEY_REQ_MAX);
		memset( (unsigned char *)req, 0, KEY_REQ_MAX);

		/*连接成功,从服务端接收字符*/
		req_len = read( nfp, (unsigned char *)req, KEY_REQ_MAX );
		if( -1 == req_len ){
			printf("read data fail !\r\n");
			return -1;
		}
		if( KEY_REQ_TYPE != req->type ){
			printf("read data fail !!!\r\n");
			return -1;
		}
		printf("read ok\r\nREC:\r\n");

		
		host_name = (char *)malloc(req->un_len);
		file_name = (char *)malloc(req->fn_len);
		key = (unsigned char *)malloc(KEY_SIZE);

		memcpy( host_name, req->buf, req->un_len );
		memcpy( file_name, req->buf+req->un_len, req->fn_len );
		memset( key, 0, KEY_SIZE );

		ret = read_key( host_name, file_name, key );
		if ( ret == -1 ){
			printf("Read Key Error !\n");
			return -1;
		}

		free(req);
		free(host_name);
		free(file_name);
		req = NULL;
		host_name = NULL;
		file_name = NULL;

		printf("key : %s\r\n",key);
		res = (KeyRes_T *)malloc(KEY_RES_MAX);
		memset( (unsigned char *)res, 0, KEY_RES_MAX );

		res->type = KEY_RES_TYPE;

		memcpy( res->buf, key, KEY_SIZE );
		// encrypt key to res->buf by RSA
//		ret = rsa_encrypt( key, res->buf );
//		if( -1 == ret ){
//			printf("key_encrypted error!!!\n");
//			close(nfp);
//			continue;
//		}

		res->buf_len = ret;

		res_len = 1+1+res->buf_len;

		/* 这里使用write向客户端发送信息，也可以尝试使用其他函数实现 */
		ret = write(nfp, (unsigned char *)res, res_len);
		if( -1 == ret ){
			printf("write fail!\r\n");
			return -1;
		}
		printf("write ok!\r\n");

		free(key);
		free(res);
		key = NULL;
		res = NULL;
		close(nfp);
	}
	close(sfp);
	return 0;
}

