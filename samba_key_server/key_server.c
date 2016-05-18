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
#include <openssl/rand.h>

#include "key_head.h"

#define KEY_ROOT_PREFIX "/home/jauntezhou/Documents/samba_key_server/key/"
#define KEY_ROOT_SUFFIX	".key"
#define FILE_ID_LEN	20
#define KEY_ROOT_LEN 	strlen(KEY_ROOT_PREFIX) + (FILE_ID_LEN + 1) * 3 - 1 + strlen(KEY_ROOT_SUFFIX)

/*
	64位字节序转换
	网络序 --> 主机序
 */
uint64_t ntoh64(uint64_t in){
	uint64_t ret = 0;
	uint32_t high,low;
	uint32_t high_h,low_h;

	low = in & 0xFFFFFFFF;
	high = (in >> 32) & 0xFFFFFFFF;
	low_h = ntohl(low); 
	high_h = ntohl(high);
	if ( low_h == low ){
		ret = high_h;
		ret <<= 32;
		ret |= low_h;
	} else {
		ret = low_h;
		ret <<= 32;   
		ret |= high_h;   
	}
	
	return ret;
}

ssize_t read_key( uint64_t devid, uint64_t inode, uint64_t extid, unsigned char *key)
{
	FILE *fp;
	char *fr;
	//size_t len = 0;
	ssize_t ret;
	char *s;
	uint16_t buf_pos = 0;

	// Set key_file_root
	fr = (char *)malloc( KEY_ROOT_LEN );
	memset( fr, 0, KEY_ROOT_LEN );
	// Add key file root prefix
	memcpy( fr + buf_pos, KEY_ROOT_PREFIX, strlen(KEY_ROOT_PREFIX) );
	buf_pos += strlen(KEY_ROOT_PREFIX);

	s = (char *)malloc(FILE_ID_LEN);
	// Add devid
	memset( s, 0, FILE_ID_LEN);
	ret = sprintf( s, "%ld", devid );
	if ( ret == -1 )
		return -1;
	printf("devid : %s\n", s);
	memcpy( fr + buf_pos, s, ret );
	buf_pos += ret;
	memcpy( fr + buf_pos, "_", 1 );
	buf_pos += 1;
	// Add inode
	memset( s, 0, FILE_ID_LEN);
	ret = sprintf( s, "%ld", inode );
	if ( ret == -1 )
		return -1;
	printf("inode : %s\n", s);
	memcpy( fr + buf_pos, s, ret );
	buf_pos += ret;
	memcpy( fr + buf_pos, "_", 1 );
	buf_pos += 1;
	// Add extid
	memset( s, 0, FILE_ID_LEN);
	ret = sprintf( s, "%ld", extid );
	if ( ret == -1 )
		return -1;
	printf("extid : %s\n", s);
	memcpy( fr + buf_pos, s, ret );
	buf_pos += ret;
	//memcpy( fr + buf_pos, "_", 1 );
	//buf_pos += 1;

	free(s);

	//memcpy( fr + buf_pos, fn, strlen(fn) );
	//buf_pos += strlen(fn);

	// Add key file root suffix
	memcpy( fr + buf_pos, KEY_ROOT_SUFFIX, strlen(KEY_ROOT_SUFFIX) );
	buf_pos += strlen(KEY_ROOT_SUFFIX);
	printf( "key save root : %s\n", fr );

	// Creat key file if it not exist
	ret = access( fr, F_OK );
	if( ret == -1 ){
		printf( "ERROR :\t KEY FILE NOT EXIST ! WRITE ONE !\n");
		fp = fopen( fr, "wb" );
		RAND_pseudo_bytes( key, KEY_SIZE );
		//memcpy( key, "JaunteZhou010205", KEY_SIZE );
		ret = fwrite( key, 1, KEY_SIZE, fp );
		if ( -1 == ret || KEY_SIZE != ret ) {
			printf("Write Key Error !\n");
			return -1;
		}
		printf("in the read function , key : %s\n", key);
		fclose(fp);
		return ret;
	}

	// Open key file
	fp = fopen( fr, "rb" );
	if (fp == NULL)
		return -1;
	// Read key
	ret = fread( key, 1, KEY_SIZE, fp );
	if ( -1 == ret ) {
		printf("Read Key Error !\n");
		return -1;
	} else if ( KEY_SIZE != ret ){
		printf("read length error !\n");
	}
	printf("in the read function , key : %s\n", key);
	// Close key file
	fclose(fp);
	free(fr);
	return ret;
}

ssize_t rsa_encrypt( unsigned char *str, unsigned char *en_str ){
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

	if( rsa_len != EN_KEY_SIZE )
		printf( "rsa encrypt key size error !\n");
	//en_str = (unsigned char *)malloc( rsa_len );
	//memset( en_str, 0, rsa_len );

	printf("key rsa encrypt\n");

	ret = RSA_public_encrypt( rsa_len, str, en_str, p_rsa, RSA_NO_PADDING );
	if( ret < 0 ){
		printf("IN FUNCTION \"rsa_encrypt\" : encrypt str error !!!\n");
		return -1;
	}

	printf("key rsa encrypt 00\n");

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

	//char *host_name;
	char *file_name = NULL;
	uint64_t devid = 0;
	uint64_t inode = 0;
	uint64_t extid = 0;
	//uint16_t buf_pos = 0;
	unsigned char *key = NULL;
	unsigned char *en_key = NULL;

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


		// Set Requst Recive Buffer
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

		//host_name = (char *)malloc(req->un_len);
		//file_name = (char *)malloc(req->fn_len);
		//memset( file_name, 0, req->fn_len );
		devid = ntoh64( req->devid );
		inode = ntoh64( req->inode );
		extid = ntoh64( req->extid );
		//buf_pos = 0;

		//memcpy( file_name, req->buf /*+ buf_pos*/, req->fn_len );
		//buf_pos += req->fn_len;
		/*
		memcpy( &devid, req->buf + buf_pos, sizeof(uint64_t) );
		buf_pos += sizeof(uint64_t);
		memcpy( &inode, req->buf + buf_pos, sizeof(uint64_t) );
		buf_pos += sizeof(uint64_t);
		memcpy( &extid, req->buf + buf_pos, sizeof(uint64_t) );
		buf_pos += sizeof(uint64_t);
		*/
		//printf( "file_name : %s !\n", file_name );
		printf( "devid : %ld !\n", devid );
		printf( "inode : %ld !\n", inode );
		printf( "extid : %ld !\n", extid );

		free(req);
		req = NULL;

		key = (unsigned char *)malloc(KEY_SIZE);
		memset( key, 0, KEY_SIZE );
		// read key from file !
		//ret = read_key( host_name, file_name, key );
		ret = read_key( devid, inode, extid, key );
		if ( ret == -1 ){
			printf("Read Key Error !\n");
			return -1;
		}

		//free(file_name);
		//file_name = NULL;

		printf( "key : %s\r\n", key );

		res = (KeyRes_T *)malloc(KEY_RES_MAX);
		memset( (unsigned char *)res, 0, KEY_RES_MAX );

		en_key = (unsigned char *)malloc(EN_KEY_SIZE);
		memset( en_key, 0, EN_KEY_SIZE );

		// encrypt key to res->buf by RSA
		ret = rsa_encrypt( key, en_key );
		if( -1 == ret || EN_KEY_SIZE != ret ){
			printf("key_encrypted error!!!\n");
			close(nfp);
			continue;
		}
		free(key);
		key = NULL;

		printf("en_key : %s\n", en_key);

		memcpy( res->buf, en_key, EN_KEY_SIZE );
		printf("res->buf : %s\n", res->buf);

		free(en_key);
		en_key = NULL;

		res->type = KEY_RES_TYPE;
		res->buf_len = ret;

		res_len = 1+1+res->buf_len;

		/* 这里使用write向客户端发送信息，也可以尝试使用其他函数实现 */
		ret = write(nfp, (unsigned char *)res, res_len);
		if( -1 == ret ){
			printf("write fail!\r\n");
			return -1;
		}
		if( res_len != ret ){
			printf("write error ! not long enough !\r\n");
		}
		printf("write ok!\r\n");

		//free(en_key);
		//en_key = NULL;
		free(res);		
		res = NULL;
		close(nfp);
	}
	close(sfp);
	return 0;
}

