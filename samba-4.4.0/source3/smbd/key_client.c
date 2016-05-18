#include "includes.h"
#include "smbd/globals.h"
#include <string.h>
#include "key_head.h"
//#include "key_client.h"

/*
	64位字节序转换
	主机序 --> 网络序
 */
uint64_t hton64(uint64_t in){
	uint64_t ret = 0;
	uint32_t high,low;
	uint32_t high_n,low_n;

	low = in & 0xFFFFFFFF;
	high = (in >> 32) & 0xFFFFFFFF;
	low_n = htonl(low);
	high_n = htonl(high);
	if ( low_n == low ){
		ret = high_n;
		ret <<= 32;
		ret |= low_n;
	} else {
		ret = low_n;
		ret <<= 32;   
		ret |= high_n;   
	}
	return ret;
}

#define LOG_FILE "/home/jauntezhou/Desktop/smb_test_log.txt"
ssize_t log_file ( char *log_data ) {
	FILE *fp;
	time_t timep;
	ssize_t ret;

	//Open log
	fp = fopen( LOG_FILE, "ab" );
	if (fp == NULL){
		fp = fopen( LOG_FILE, "wb" );
		if(fp == NULL)
			return -1;

	}
	
	//Write time to log
	time (&timep);
	ret = fwrite( asctime(gmtime(&timep)), 1, strlen(asctime(gmtime(&timep))), fp );
	if( ret != strlen(asctime(gmtime(&timep))) )
		return -1;

	//Write log_data to log
	ret = fwrite( log_data, 1, strlen(log_data), fp );
	if( ret != strlen(log_data) )
		return -1;

	//Keep format
	ret = fwrite( "\n", 1, 1, fp );
	if( ret != 1 )
		return -1;

	//Close log
	fclose( fp );

	return strlen(log_data);
}

ssize_t rsa_decrypt( unsigned char *en_str, unsigned char *de_str ){
	RSA *p_rsa;
	FILE *fp;
	int rsa_len;
	ssize_t ret;

	fp = fopen( RSA_PRIVATE_KEY, "r" );
	if( fp == NULL ){
		log_file("open key file error");
		return -1;
	}

	p_rsa = PEM_read_RSAPrivateKey( fp, NULL, NULL, NULL );
	if( p_rsa == NULL ){
		log_file("read RSA key file error");
		return -1;
	}
	rsa_len = RSA_size( p_rsa );

	//de_str = (unsigned char *)malloc( rsa_len );
	//memset( de_str, 0, rsa_len );

	ret = RSA_private_decrypt( rsa_len, en_str, de_str, p_rsa, RSA_NO_PADDING );
	if( ret < 0 )
		return -1;

	RSA_free(p_rsa);
	fclose(fp);
	return rsa_len;
}

ssize_t get_key_from_keyserver( files_struct *fsp, unsigned char *key )
{
	int cfd;
	int sin_size;
	ssize_t ret;

	KeyReq_T *req;
	ssize_t req_len;
	KeyRes_T *res;
	ssize_t res_len;

	unsigned char *de_key = NULL;

	struct sockaddr_in s_add,c_add; // 存储服务端和本端的ip、端口等信息结构体
	unsigned short portnum = SERVER_PORT;  // 服务端使用的通信端口，可以更改，需和服务端相同

	log_file("Hello,welcome to client !\r\n");

	// 建立socket 使用因特网，TCP流传输
	cfd = socket(AF_INET, SOCK_STREAM, 0);
	if( -1 == cfd ){
		log_file("socket fail ! \r\n");
		return -1;
	}
	log_file("socket ok !\r\n");

	// 构造服务器端的ip和端口信息，具体结构体可以查资料
	bzero( &s_add, sizeof(struct sockaddr_in) );
	s_add.sin_family = AF_INET;
	// ip转换为4字节整形，使用时需要根据服务端ip进行更改
	s_add.sin_addr.s_addr = inet_addr( SERVER_IP );
	// 这里htons是将short型数据字节序由主机型转换为网络型
	s_add.sin_port = htons( portnum );

	// 这里打印出的是小端和我们平时看到的是相反的。
	printf("s_addr = %#x ,port : %#x\r\n",s_add.sin_addr.s_addr,s_add.sin_port); 


	// 客户端连接服务器，参数依次为socket文件描述符，地址信息，地址结构大小
	ret = connect(cfd,(struct sockaddr *)(&s_add), sizeof(struct sockaddr));
	if( -1 == ret ){
		log_file("connect fail !\r\n");
		return -1;
	}
	log_file("connect ok !\r\n");
	
	//////////////////////////////////////////////
	//char * host_name = fsp->conn->sconn->remote_hostname;
	//uint32_t hostname_size = strlen(host_name);
	//char * file_name;
	//file_name = (char *)malloc( strlen(fsp_str_dbg(fsp)) );
	//memset( file_name, 0, strlen(fsp_str_dbg(fsp)) );
	//memcpy( file_name, fsp_str_dbg(fsp), strlen(fsp_str_dbg(fsp)) );
	//uint32_t filename_size = strlen(file_name);

	//int fd = fsp->fh->fd;
	//uint64_t devid = hton64( fsp->file_id.devid );
	//uint64_t inode = hton64( fsp->file_id.inode );
	//uint64_t extid = hton64( fsp->file_id.extid );
	//uint16_t buf_pos = 0;
	//////////////////////////////////////////////

	req = (KeyReq_T *)malloc(KEY_REQ_MAX);
	memset( (unsigned char *)req, 0, KEY_REQ_MAX );

	req->type = KEY_REQ_TYPE;
	//req->un_len = strlen( host_name );
	//req->fn_len = strlen( file_name );

	req->devid = hton64( fsp->file_id.devid );
	req->inode = hton64( fsp->file_id.inode );
	req->extid = hton64( fsp->file_id.extid );
	//memcpy( req->buf, file_name, req->fn_len );
	/*
	memcpy( req->buf + buf_pos, file_name, req->fn_len );
	buf_pos += req->fn_len;
	memcpy( req->buf + buf_pos, &devid, sizeof(uint64_t) );
	buf_pos += sizeof(uint64_t);
	memcpy( req->buf + buf_pos, &inode, sizeof(uint64_t) );
	buf_pos += sizeof(uint64_t);
	memcpy( req->buf + buf_pos, &extid, sizeof(uint64_t) );
	buf_pos += sizeof(uint64_t);
	*/
	req_len = 1 + 8 + 8 + 8;
	//req_len = 1 + 1 + 8 + 8 + 8 + req->fn_len;

	// 这里使用write向server发送信息
	ret = write( cfd, (unsigned char *)req, req_len );
	if(-1 == ret || req_len != ret){
		log_file("write req to server fail!\r\n");
		return -1;
	}
	log_file("write ok!\r\n");
	//log_file("file_name :");
	//log_file( file_name );

	free(req);
	req = NULL;
	//free(file_name);
	//file_name = NULL;

	//
	res = (KeyRes_T *)malloc(KEY_RES_MAX);
	memset( (unsigned char *)res, 0, KEY_RES_MAX );

	de_key = (unsigned char *)malloc(EN_KEY_SIZE);
	memset( de_key, 0, EN_KEY_SIZE );

	// 连接成功,从服务端接收字符
	res_len = read(cfd, (unsigned char *)res, KEY_RES_MAX);
	if( -1 == res_len ){
		log_file("read data fail !\r\n");
		return -1;
	} else if ( res_len != 1+1+EN_KEY_SIZE ){
		log_file("read data not long enough !\r\n");
		return -1;
	}
	
	if ( res->buf_len != EN_KEY_SIZE ){
		log_file("buf_len wrong!!!\r\n");
	}

	if( KEY_RES_TYPE != res->type ){
		log_file("read data type fail !!!\r\n");
		return -1;
	}
	log_file("read ok\r\nREC:\r\n");

	log_file( "before decrypt:" );
	log_file( "buf :" );
	log_file( res->buf );
	log_file( "key :" );
	log_file( key );
	log_file( "de_key :" );
	log_file( de_key );
	// rsa decrypt
	ret = rsa_decrypt( res->buf, de_key );
	if( ret == -1 ){
		log_file( "Decrypt Error !" );
		return -1;
	}
	if( ret != EN_KEY_SIZE ){
		printf("key length error!\n");
		return -1;
	}
	memcpy( key, de_key, KEY_SIZE );
	log_file( "after decrypt:" );
	log_file( "key :" );
	log_file( key );
	log_file( "de_key :" );
	log_file( de_key );

	free(res);
	res = NULL;
	free(de_key);
	de_key = NULL;

	close(cfd); // 关闭连接，本次通信完成

	return 0;
}
