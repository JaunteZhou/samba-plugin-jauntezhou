#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "includes.h"
#include "printing.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "smbprofile.h"


#include <openssl/aes.h>  
#include <openssl/rand.h>

#include "fileio_hook.h"
#include "key_head.h"
#include "key_client.h"

#define BLOCK_SIZE 	1024
#define EN_BLOCK_SIZE 	16

ssize_t
encrypt_hook( char *cipher_data, 
		char *plain_data,
		size_t n,
		unsigned char *rkey )
{
	size_t last_data_num = 0;
	size_t block_num = 0;
	size_t en_sum = 0;

	//Internal key.  
	AES_KEY         en_key;

	//log_file( rkey );

	//Set Encrypt Key
	AES_set_encrypt_key( rkey, 8 * KEY_SIZE, &en_key );

	block_num = n / EN_BLOCK_SIZE;
	last_data_num = n % EN_BLOCK_SIZE;

	//Encrypt data
	while(block_num){
		AES_encrypt( (plain_data+en_sum), (cipher_data+en_sum), &en_key);
		en_sum += EN_BLOCK_SIZE;
		block_num -= 1;
	}
	if( last_data_num ){
		memcpy( (cipher_data+en_sum), (plain_data+en_sum), last_data_num );
		en_sum += last_data_num;
	}

	return en_sum;
}

ssize_t
decrypt_hook( char *plain_data,
		char *cipher_data, 
		size_t n,
		unsigned char *rkey )
{
	size_t last_data_num = 0;
	size_t block_num = 0;
	size_t de_sum = 0;

	//Internal key.  
	AES_KEY         de_key;

	//Set Encrypt Key
	AES_set_decrypt_key( rkey, 8 * KEY_SIZE, &de_key );

	block_num = n / EN_BLOCK_SIZE;
	last_data_num = n % EN_BLOCK_SIZE;

	//Encrypt data
	while( block_num ){
		AES_decrypt( (cipher_data+de_sum), (plain_data+de_sum), &de_key);
		de_sum += EN_BLOCK_SIZE;
		block_num -= 1;
	}
	if( last_data_num ){
		memcpy( (cipher_data+de_sum), (plain_data+de_sum), last_data_num );
		de_sum += last_data_num;
	}

	return de_sum;
}

///////////////////////////////////////////////
//Write file & Encrypt file
///////////////////////////////////////////////
ssize_t 
write_file_hook(files_struct *fsp,
		const char *data,
		size_t n,
		off_t pos)
{
	// step1: 保存原始的数据偏移及大小
	ssize_t	 	ret = -1;
	ssize_t		ret_sum = 0;
	//ssize_t		en_sum = 0;
	uint16_t 	file_n_wt = 0;
	//uint16_t	file_n_wt = 0;
	//size_t		en_block_num = 0;
	size_t		file_n_rest = n;
	size_t	 	file_n_src = n;
	//uint16_t	file_n_last = 0;
	
	off_t 		file_pos_src = pos;
	off_t 		file_pos_last;
	//size_t		wtd_block_num;
	//size_t		num_block_wting = 0;

	size_t		wtd_data_len = 0;

	char 		*plain_data = NULL;
	char 		*encrypted_data = NULL;

	// get key when begin write file
	if( pos == 0 || pos == -1 || fsp->key == NULL ){
		fsp->key = (unsigned char *)malloc(KEY_SIZE);
		memset( fsp->key, 0, KEY_SIZE );
		log_file( "when pos = 0, get key Start !\n\n" );
		ret = get_key_from_keyserver( fsp, fsp->key );
	}

	log_file( "WFH :\t write_file_hook Start !\n\n" );

	//wtd_block_num = file_pos_src / EN_BLOCK_SIZE;
	file_pos_last = (file_pos_src / EN_BLOCK_SIZE) * EN_BLOCK_SIZE;

	if( file_pos_src == -1 ) {
		file_pos_last = -1;
		log_file( "WFH :\t write_file_hook Start ! pos == -1\n\n" );
	} else if ( file_pos_src == 0 ){
		file_pos_last = 0;
		log_file( "WFH :\t write_file_hook Start ! pos == 0\n\n" );
	}

	if ( file_pos_src > file_pos_last ){
		if( file_pos_last == -1)
			log_file( "WFH :\t write_file_hook Start read last data, pos == -1 !\n\n" );
		else
			log_file( "WFH :\t write_file_hook Start read last data!, pos != -1 !\n\n" );

		wtd_data_len = file_pos_src - file_pos_last;
		file_n_wt = (file_n_src + wtd_data_len) >= EN_BLOCK_SIZE ?
				EN_BLOCK_SIZE : file_n_src + wtd_data_len;

		plain_data = (char *)malloc(file_n_wt);
		memset(plain_data, 0, file_n_wt);

		encrypted_data = (char *)malloc(file_n_wt);
		memset(encrypted_data, 0, file_n_wt);
		
		//read last_n_data
		ret = SMB_VFS_PREAD(fsp, plain_data, wtd_data_len, file_pos_last);
		if ( ret != EN_BLOCK_SIZE ){
			log_file( "WFH ERROR :\t read last data wrong !\n\n" );
			return -1;
		}

		//decrypt_hook();
		memcpy( plain_data, data + ret_sum, file_n_wt - wtd_data_len );
		encrypt_hook( encrypted_data, plain_data, file_n_wt, fsp->key );

		ret = vfs_pwrite_data(NULL, fsp, encrypted_data, file_n_wt, file_pos_last);
		if (ret == -1) {
			log_file( "WFH ERROR :\t write error !\n\n" );
			return -1;
		} else if ( ret != file_n_wt ) {
			log_file( "WFH ERROR :\t write error !\n\n" );
			return -1;
		}

		file_pos_last += file_n_wt;
		ret_sum += (file_n_wt - wtd_data_len);
		file_n_rest -= (file_n_wt - wtd_data_len);

		free(plain_data);
		plain_data = NULL;
		free(encrypted_data);
		encrypted_data = NULL;
	}

	log_file( "WFH :\t write_file_hook Start write data !\n\n" );
	while( file_n_rest > 0 ){
		if( file_n_rest >= BLOCK_SIZE ){
			file_n_wt = BLOCK_SIZE;
		} else {
			file_n_wt = file_n_rest;
		}

		//Init Buffer
		plain_data = (char *)malloc(file_n_wt);
		memset(plain_data, 0, file_n_wt);
		memcpy( plain_data, data + ret_sum, file_n_wt );

		encrypted_data = (char *)malloc(file_n_wt);
		memset( encrypted_data, 0, file_n_wt );

		log_file( "WFH :\t Start encrypt data !\n\n" );

		encrypt_hook( encrypted_data, plain_data, file_n_wt, fsp->key );

		log_file( "WFH :\t Start write to cashe !\n\n" );

		/*step4: 数据存盘 */
		if (file_pos_last == -1) {
			log_file( "WFH :\t Start write from beginning !\n\n" );
			//从文件开头写
    			ret = vfs_write_data(NULL, fsp, encrypted_data, file_n_wt);
		} else {
			log_file( "WFH :\t Start write from middle !\n\n" );
    			//从偏移量‘pos’开始写
			ret = vfs_pwrite_data(NULL, fsp, encrypted_data, file_n_wt, file_pos_last);
		}
		log_file( "WFH :\t write to cashe End !\n\n" );

		//xie ru cuo wu huo xie ru bu wanzheng
		if (ret == -1) {
			log_file( "WFH ERROR :\t write error !\n\n" );
			return -1;
		} else if ( ret != file_n_wt ) {
			log_file( "WFH ERROR :\t write error !\n\n" );
			return -1;
		}
		log_file( "WFH :\t Start write a part !\n\n" );

		file_pos_last += file_n_wt;
		ret_sum += file_n_wt;
		file_n_rest -= file_n_wt;

		free(plain_data);
		plain_data = NULL;
		free(encrypted_data);
		encrypted_data = NULL;
	}

	log_file( "WFH :\t write_file_hook End !\n\n" );

	if( fsp->fsp_name->st.st_ex_size == 1708 )
		log_file("1708\n\n");
	if( fsp->fsp_name->st.st_ex_size == 1714 )
		log_file("1714\n\n");
	if( fsp->fsp_name->st.st_ex_size == 719500 )
		log_file("719500\n\n");
	if( fsp->fsp_name->st.st_ex_size == 719550 )
		log_file("719550\n\n");
	
	return ret_sum;
}

///////////////////////////////////////////////
//Read file & Decrypt file
///////////////////////////////////////////////
ssize_t 
read_file_hook(files_struct *fsp,
		char *data,
		size_t n,
		off_t pos)
{
	// step1: 保存原始的数据偏移及大小
	ssize_t	 	ret = -1;
	ssize_t	 	ret_sum = 0;
	//ssize_t	 	de_sum = 0;

	//uint16_t	file_n_rd = 0;
	//size_t		num_de_block = 0;
	//size_t	 	rdd_block_num = 0;
	size_t	 	rdd_data_len = 0;

	size_t	 	file_n_src = n;
	size_t	 	file_n_rest = n;
	//uint16_t	file_n_last = 0;
	uint16_t	file_n_rd = 0;

	off_t	 	file_pos_src = pos;
	off_t	 	file_pos_last;


	//Buffer for Encrypted Data
	char *encrypted_data;
	char *decrypted_data;

	// get key when begin write file
	if( pos == 0 || pos == -1 || fsp->key == NULL ){
		fsp->key = (unsigned char *)malloc(KEY_SIZE);
		memset( fsp->key, 0, KEY_SIZE );
		log_file( "when pos = 0, get key Start !\n\n" );
		ret = get_key_from_keyserver( fsp, fsp->key );
	}

	log_file( "RFH :\t start read_file_hook ~\n\n" );
	
	//rdd_block_num = file_pos_src / EN_BLOCK_SIZE;
	file_pos_last = (file_pos_src / EN_BLOCK_SIZE) * EN_BLOCK_SIZE;

	if ( file_pos_src > file_pos_last ){
		log_file( "RFH :\t start read last data ! ~\n\n" );
		rdd_data_len = file_pos_src - file_pos_last;
		file_n_rd = ( file_n_src + rdd_data_len ) >= EN_BLOCK_SIZE ?
				EN_BLOCK_SIZE : file_n_src + rdd_data_len;

		//Init Buffer
		encrypted_data = (char *)malloc(file_n_rd);
		memset(encrypted_data, 0, file_n_rd);
		decrypted_data = (char *)malloc(file_n_rd);
		memset(decrypted_data, 0, file_n_rd);

		log_file( "RFH :\t start PREAD ~\n\n" );

		//Read Encrypted Data
		ret = SMB_VFS_PREAD( fsp, encrypted_data, file_n_rd, file_pos_last );
		if ( ret != file_n_rd ) {
			log_file( "PREAD ERROR :\t main read not enough~\n\n" );
			free(encrypted_data);
			free(decrypted_data);
			return ret_sum;
		}
		if ( ret == -1 ){
			log_file( "PREAD ERROR :\t main read none ~\n\n" );
			free(encrypted_data);
			free(decrypted_data);
			return -1;
		}

		decrypt_hook( decrypted_data, encrypted_data, file_n_rd, fsp->key );
		memcpy( data + ret_sum, decrypted_data + rdd_data_len, file_n_rd - rdd_data_len );

		file_pos_last += file_n_rd;
		file_n_rest -= (file_n_rd - rdd_data_len);
		ret_sum += (file_n_rd - rdd_data_len);

		free(encrypted_data);
		encrypted_data = NULL;
		free(decrypted_data);
		decrypted_data = NULL;
	}

	log_file( "RFH :\t start read ~\n\n" );
	while( file_n_rest > 0 ){
		log_file( "RFH :\t read loop start ! ~\n\n" );
		if( file_n_rest >= BLOCK_SIZE ){
			file_n_rd = BLOCK_SIZE;
		} else {
			log_file( "RFH :\t read less than EN_BLOCK ! ~\n\n" );
			file_n_rd = file_n_rest;
		}

		//Init Buffer
		encrypted_data = (char *)malloc(file_n_rd);
		memset(encrypted_data, 0, file_n_rd);
		decrypted_data = (char *)malloc(file_n_rd);
		memset(decrypted_data, 0, file_n_rd);

		log_file( "RFH :\t start PREAD ~\n\n" );

		//Read Encrypted Data
		ret = SMB_VFS_PREAD( fsp, encrypted_data, file_n_rd, file_pos_last );
		if ( ret != file_n_rd ) {
			log_file( "PREAD ERROR :\t main read not enough~\n\n" );
			free(encrypted_data);
			free(decrypted_data);
			break;
		}
		if ( ret == -1 ){
			log_file( "PREAD ERROR :\t main read none ~\n\n" );
			free(encrypted_data);
			free(decrypted_data);
			return -1;
		}

		log_file( "RFH :\t start decrypted ~\n\n" );
		//log_file( encrypted_data );

		decrypt_hook( decrypted_data, encrypted_data, file_n_rd, fsp->key );
		memcpy( data + ret_sum, decrypted_data, file_n_rd );
		
		file_pos_last += file_n_rd;
		file_n_rest -= file_n_rd;
		ret_sum += file_n_rd;

		free(encrypted_data);
		encrypted_data = NULL;
		free(decrypted_data);
		decrypted_data = NULL;
	}
	log_file( "RFH :\t end read file hook ~\n\n" );

	return ret_sum;
}
