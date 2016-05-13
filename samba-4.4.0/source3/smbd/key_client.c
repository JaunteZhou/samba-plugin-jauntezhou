#include "includes.h"
#include "smbd/globals.h"
#include <string.h>
#include "key_head.h"
//#include "key_client.h"

#define LOG_FILE "/home/jauntezhou/Desktop/smb_test_log.txt"
ssize_t log_file ( char *log_data ) {
	FILE *fp;
	time_t timep;
	ssize_t ret;
	// test
	fp = fopen( LOG_FILE, "ab" );
	if (fp == NULL){
		fp = fopen( LOG_FILE, "wb" );
		if(fp == NULL)	return -1;
		//DEBUG("Open Key TXT ERROR !!!");
	}
	
	time (&timep);
	ret = fwrite( asctime(gmtime(&timep)), 1, strlen(asctime(gmtime(&timep))), fp );
	if( ret != strlen(asctime(gmtime(&timep))) )
		return -1;
	ret = fwrite( log_data, 1, strlen(log_data), fp );
	if( ret != strlen(log_data) )
		return -1;
	fclose( fp );
	// test end
	return 1;
}

ssize_t rsa_decrypt( unsigned char *en_str, unsigned char *str_de ){
	RSA *p_rsa;
	FILE *fp;
	int rsa_len;
	ssize_t ret;

	fp = fopen( RSA_PRIVATE_KEY, "r" );
	if( fp == NULL ){
		perror("open key file error");
		return -1;
	}

	p_rsa = PEM_read_RSAPrivateKey( fp, NULL, NULL, NULL );
	if( p_rsa == NULL ){
		ERR_print_errors_fp(stdout);
		return -1;
	}
	rsa_len = RSA_size( p_rsa );

	str_de = (unsigned char *)malloc(rsa_len+1);
	memset( str_de, 0, rsa_len+1 );

	ret = RSA_private_decrypt( rsa_len, en_str, str_de, p_rsa, RSA_NO_PADDING );
	if( ret < 0 ){
		return -1;
	}

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
	unsigned char *key_en;

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
	char * host_name = fsp->conn->sconn->remote_hostname;
	//uint32_t hostname_size = strlen(host_name);
	char * file_name = fsp_str_dbg(fsp);
	//uint32_t filename_size = strlen(file_name);
	//////////////////////////////////////////////
	
	req = (KeyReq_T *)malloc(KEY_REQ_MAX);
	memset( (unsigned char *)req, 0, KEY_REQ_MAX );

	req->type = KEY_REQ_TYPE;
	req->un_len = strlen( host_name );
	req->fn_len = strlen( file_name );
	memcpy( req->buf, host_name, strlen(host_name));
	memcpy( req->buf+req->un_len, file_name, strlen(file_name) );

	req_len = 1+1+1+ strlen(host_name) + strlen(file_name);

	// 这里使用write向server发送信息
	ret = write( cfd, (unsigned char *)req, req_len );
	if(-1 == ret || req_len != ret){
		log_file("write req to server fail!\r\n");
		return -1;
	}
	log_file("write ok!\r\n");

	free(req);
	req = NULL;


	res = (KeyRes_T *)malloc(KEY_RES_MAX);
	memset( (unsigned char *)res, 0, KEY_RES_MAX );

//	key_en = (unsigned char *)malloc(KEY_EN_SIZE);
//	memset( key_en, 0, KEY_EN_SIZE );		//128

	// 连接成功,从服务端接收字符
	res_len = read(cfd, (unsigned char *)res, KEY_RES_MAX);
	if( -1 == res_len ){
		log_file("read data fail !\r\n");
		return -1;
	} else if ( res_len != 1+1+KEY_SIZE ){
		log_file("read data note long enough !\r\n");
		return -1;
	}
	
	if ( res->buf_len != KEY_SIZE ){
		log_file("buf_len wrong!!!\r\n");
	}

	if( KEY_RES_TYPE != res->type ){
		log_file("read data type fail !!!\r\n");
		return -1;
	}
	log_file("read ok\r\nREC:\r\n");

	memcpy( key/*_en*/, res->buf, KEY_SIZE );
//	strcpy( key, res->buf );

	log_file( res->buf );
	log_file( key );
	// rsa decrypt
//	ret = rsa_decrypt( key_en, key );
//	if( ret != KEY_SIZE ){
//		printf("key length error!\n");
//		return -1;
//	}
//	printf( "after decrypt:%s\n", key );

	free(res);
//	free(key_en);
	res = NULL;
//	key_en = NULL;

	//getchar(); // 此句为使程序暂停在此处，可以使用netstat查看当前的连接
	close(cfd); // 关闭连接，本次通信完成

	return 0;
}
