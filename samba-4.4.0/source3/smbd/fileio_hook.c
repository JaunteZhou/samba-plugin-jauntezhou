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
	ssize_t		en_sum = 0;
	uint16_t 	file_n_temp = 0;
	uint16_t	wt_buf_len = 0;
	size_t		en_block_num = 0;
	size_t		file_n_rest = n;
	size_t	 	file_n_src = n;
	uint16_t	file_n_last = 0;
	
	off_t 		file_pos_src = pos;
	off_t 		file_pos_last;
	size_t		wtd_block_num;
	size_t		num_block_wting = 0;

	size_t		wtd_data_len = 0;

	uint8_t set_num = 0;

	char 		*temp_plaint_data = NULL;
	char 		*plaint_data = NULL;
	char 		*encrypted_data = NULL;

	//128bits key.
	//unsigned char   rkey[KEY_SIZE] = "JaunteZhou010502";
	unsigned char *rkey;
	//rkey = (unsigned char *)malloc(KEY_SIZE);
	//ret = get_key_from_keyserver( fsp, rkey );

	// get key when begin write file
	if( pos == 0 || fsp->key == NULL ){
		fsp->num_block = 0;
		fsp->key = (unsigned char *)malloc(KEY_SIZE);
		memset( fsp->key, 0, KEY_SIZE );
		log_file( "WFH :\t when pos = 0, get key Start !\n\n" );
		ret = get_key_from_keyserver( fsp, fsp->key );
	} else if ( pos == -1 ){
		fsp->num_block = 0;
		fsp->key = (unsigned char *)malloc(KEY_SIZE);
		memset( fsp->key, 0, KEY_SIZE );
		log_file( "WFH :\t when pos = -1, get key Start !\n\n" );
		ret = get_key_from_keyserver( fsp, fsp->key );
	}
	rkey = fsp->key;
	log_file( rkey );


	//Internal key.  
	AES_KEY         en_key;
	int 		num_bits = 0;

	//Set Entrypt Key
	num_bits = 8 * KEY_SIZE;
	AES_set_encrypt_key(rkey, num_bits, &en_key);

	log_file( "WFH :\t write_file_hook Start !\n\n" );

	wtd_block_num = file_pos_src / EN_BLOCK_SIZE;
	file_pos_last = wtd_block_num * EN_BLOCK_SIZE;

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
		file_n_temp = (file_n_src + wtd_data_len) >= EN_BLOCK_SIZE ?
				EN_BLOCK_SIZE : file_n_src + wtd_data_len;

		//set_num = EN_BLOCK_SIZE - file_n_temp;
		if (set_num == 0){
			log_file("set 0 to mem !\n\n");
		} else if (set_num == 4){
			log_file("set 4 to mem !\n\n");
		}

		plaint_data = (char *)malloc(EN_BLOCK_SIZE);
		memset(plaint_data, 0, EN_BLOCK_SIZE);

		encrypted_data = (char *)malloc(EN_BLOCK_SIZE);
		memset(encrypted_data, 0, EN_BLOCK_SIZE);
		
		//read last_n_data
		ret = SMB_VFS_PREAD(fsp, plaint_data, wtd_data_len, file_pos_last);
		if ( ret != EN_BLOCK_SIZE ){
			log_file( "WFH ERROR :\t read last data wrong !\n\n" );
			return -1;
		}

		if ( file_n_temp == EN_BLOCK_SIZE ){
			//decrypted last_n_data to plaint_data
			//AES_KEY         de_key;
			//num_bits = 8 * KEY_SIZE;
			//AES_set_decrypt_key(rkey, num_bits, &de_key);
			//AES_decrypt( encrypted_data, plaint_data, &de_key );
			memcpy( plaint_data, data+ret_sum, file_n_temp - wtd_data_len );
			AES_encrypt( plaint_data, encrypted_data, &en_key );
		} else {
			memcpy( plaint_data, data+ret_sum, file_n_temp - wtd_data_len );
			memcpy( encrypted_data, plaint_data, EN_BLOCK_SIZE );
		}

		ret = vfs_pwrite_data(NULL, fsp, encrypted_data, file_n_temp, file_pos_last);
		if (ret == -1) {
			log_file( "WFH ERROR :\t write error !\n\n" );
			return -1;
		} else if ( ret != wt_buf_len ) {
			log_file( "WFH ERROR :\t write error !\n\n" );
			return -1;
		}

		file_pos_last += file_n_temp;
		ret_sum += (file_n_temp - wtd_data_len);
		file_n_rest -= (file_n_temp - wtd_data_len);

		free(plaint_data);
		plaint_data = NULL;
		free(encrypted_data);
		encrypted_data = NULL;
	}

	log_file( "WFH :\t write_file_hook Start write data !\n\n" );
	while( file_n_rest > 0 ){
		if( file_n_rest >= BLOCK_SIZE ){
			file_n_temp = BLOCK_SIZE;
		} else {
			file_n_temp = file_n_rest;
		}

		en_block_num = file_n_temp / EN_BLOCK_SIZE;
		wt_buf_len = file_n_temp;
		size_t last_data = file_n_temp % EN_BLOCK_SIZE;

		//set_num = wt_buf_len - file_n_temp;
		if (set_num == 0){
			log_file("set 0 to mem !\n\n");
		} else if (set_num == 4){
			log_file("set 4 to mem !\n\n");
		}

		//Init Buffer
		plaint_data = (char *)malloc(wt_buf_len);
		memset(plaint_data, 0, wt_buf_len);
		memcpy( plaint_data, data + ret_sum, file_n_temp );

		encrypted_data = (char *)malloc(wt_buf_len);
		memset( encrypted_data, 0, wt_buf_len );

		log_file( "WFH :\t Start encrypt data !\n\n" );
		en_sum = 0;
		while(en_block_num){
			AES_encrypt( (plaint_data+en_sum), (encrypted_data+en_sum), &en_key);
			en_sum += EN_BLOCK_SIZE;
			en_block_num -= 1;
		}
		if( last_data ){
			memcpy( (encrypted_data+en_sum), (plaint_data+en_sum), last_data );
		}

		log_file( "WFH :\t Start write to cashe !\n\n" );

		/*step4: 数据存盘 */
		if (file_pos_last == -1) {
			log_file( "WFH :\t Start write from beginning !\n\n" );
			//从文件开头写
    			ret = vfs_write_data(NULL, fsp, encrypted_data, wt_buf_len);
		} else {
			log_file( "WFH :\t Start write from middle !\n\n" );
    			//从偏移量‘pos’开始写
			ret = vfs_pwrite_data(NULL, fsp, encrypted_data, wt_buf_len, file_pos_last);
		}
		log_file( "WFH :\t write to cashe End !\n\n" );

		//xie ru cuo wu huo xie ru bu wanzheng
		if (ret == -1) {
			log_file( "WFH ERROR :\t write error !\n\n" );
			return -1;
		} else if ( ret != wt_buf_len ) {
			log_file( "WFH ERROR :\t write error !\n\n" );
			return -1;
		}
		log_file( "WFH :\t Start write a part !\n\n" );

		file_pos_last += wt_buf_len;
		ret_sum += file_n_temp;
		file_n_rest -= file_n_temp;

		///////////////////////////////////
		//log_file( "plaint_data :\n" );
		//log_file( plaint_data );
		//log_file( "encrypted_data :\n" );
		//log_file( encrypted_data );

		free(plaint_data);
		plaint_data = NULL;
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
	ssize_t	 	de_sum = 0;

	uint16_t	rd_buf_len = 0;
	size_t		num_de_block = 0;
	size_t	 	rdd_block_num = 0;
	size_t	 	rdd_data_len = 0;

	size_t	 	file_n_src = n;
	size_t	 	file_n_rest = n;
	uint16_t	file_n_last = 0;
	uint16_t	file_n_temp = 0;

	off_t	 	file_pos_src = pos;
	off_t	 	file_pos_last;


	//Buffer for Encrypted Data
	char *encrypted_data;
	char *decrypted_data;

	int num_bits = 0;
	//128bits en_key.  
	//unsigned char   rkey[KEY_SIZE] = "JaunteZhou010502";
	unsigned char *rkey;
	//rkey = (unsigned char *)malloc(KEY_SIZE);
	//ret = get_key_from_keyserver( fsp, rkey );

	// get key when begin write file
	if( pos == 0 || fsp->key == NULL ){
		fsp->num_block = 0;
		fsp->key = (unsigned char *)malloc(KEY_SIZE);
		memset( fsp->key, 0, KEY_SIZE );
		log_file( "when pos = 0, get key Start !\n\n" );
		ret = get_key_from_keyserver( fsp, fsp->key );
	} else if ( pos == -1 ){
		fsp->num_block = 0;
		fsp->key = (unsigned char *)malloc(KEY_SIZE);
		memset( fsp->key, 0, KEY_SIZE );
		log_file( "when pos = -1, get key Start !\n\n" );
		ret = get_key_from_keyserver( fsp, fsp->key );
	}
	rkey = fsp->key;
	log_file( rkey );

	//Internal key.  
	AES_KEY         de_key; 

	//Decrypt Data
	num_bits = 8 * KEY_SIZE;  
	AES_set_decrypt_key(rkey, num_bits, &de_key); 

	log_file( "RFH :\t start read_file_hook ~\n\n" );
	
	rdd_block_num = file_pos_src / EN_BLOCK_SIZE;
	file_pos_last = rdd_block_num * EN_BLOCK_SIZE;

	if ( file_pos_src > file_pos_last ){
		log_file( "RFH :\t start read last data ! ~\n\n" );
		rdd_data_len = file_pos_src - file_pos_last;
		file_n_temp = ( file_n_src + rdd_data_len ) >= EN_BLOCK_SIZE ?
				EN_BLOCK_SIZE : file_n_src + rdd_data_len;

		//Init Buffer
		encrypted_data = (char *)malloc(file_n_temp);
		memset(encrypted_data, 0, file_n_temp);
		decrypted_data = (char *)malloc(file_n_temp);
		memset(decrypted_data, 0, file_n_temp);

		log_file( "RFH :\t start PREAD ~\n\n" );

		//Read Encrypted Data
		ret = SMB_VFS_PREAD( fsp, encrypted_data, file_n_temp, file_pos_last );

		if( file_n_temp == EN_BLOCK_SIZE ){
			AES_decrypt( encrypted_data, decrypted_data, &de_key );
		} else {
			memcpy( decrypted_data, encrypted_data, file_n_temp );
		}
		memcpy( data + ret_sum, decrypted_data + rdd_data_len, file_n_temp - rdd_data_len );

		file_pos_last += file_n_temp;
		file_n_rest -= (file_n_temp - rdd_data_len);
		ret_sum += (file_n_temp - rdd_data_len);

		free(encrypted_data);
		encrypted_data = NULL;
		free(decrypted_data);
		decrypted_data = NULL;
	}

	log_file( "RFH :\t start read ~\n\n" );
	while( file_n_rest > 0 ){
		log_file( "RFH :\t read loop start ! ~\n\n" );
		if( file_n_rest >= BLOCK_SIZE ){
			file_n_temp = BLOCK_SIZE;
		} else {
			log_file( "RFH :\t read less than EN_BLOCK ! ~\n\n" );
			file_n_temp = file_n_rest;
		}

		num_de_block = file_n_temp / EN_BLOCK_SIZE;
		rd_buf_len = file_n_temp;
		size_t last_data = file_n_temp % EN_BLOCK_SIZE;

		//Init Buffer
		encrypted_data = (char *)malloc(rd_buf_len);
		memset(encrypted_data, 0, rd_buf_len);
		decrypted_data = (char *)malloc(rd_buf_len);
		memset(decrypted_data, 0, rd_buf_len);

		log_file( "RFH :\t start PREAD ~\n\n" );

		//Read Encrypted Data
		ret = SMB_VFS_PREAD( fsp, encrypted_data, rd_buf_len, file_pos_last );
		if ( ret != rd_buf_len ) {
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

		de_sum = 0;
		while(num_de_block){
			AES_decrypt( (encrypted_data+de_sum), (decrypted_data+de_sum), &de_key );
			de_sum += EN_BLOCK_SIZE;
			num_de_block -= 1;
		}
		if( last_data ){
			memcpy( (decrypted_data+de_sum), (encrypted_data+de_sum), last_data );
		}

		/*/////////////////////////////////////////
		unsigned char flag = 0;
		uint8_t flag_num = 0;
		off_t flag_pos = file_n_temp-1;
		flag = decrypted_data[ flag_pos ];
		if (flag == 4){
			log_file("find 4 in mem !\n\n");
		}
		while ( decrypted_data[ flag_pos ] == flag ){
			//log_file( "find 0 in decrypted data, reduce it !\n\n" );
			flag_pos -= 1;
			flag_num += 1;
			if( flag_num == flag ){
				log_file( "find 0 in decrypted data, reduce it !\n\n" );
				file_n_temp -= flag_num;
				fsp->fsp_name->st.st_ex_size -= flag_num;
				fsp->fnum -= flag_num;
				break;
			}
		}

		*//////////////////////////////////////////

		memcpy( data + ret_sum, decrypted_data, file_n_temp );
		
		file_pos_last += rd_buf_len;
		file_n_rest -= file_n_temp;
		ret_sum += file_n_temp;

		free(encrypted_data);
		encrypted_data = NULL;
		free(decrypted_data);
		decrypted_data = NULL;
	}

	log_file( "RFH :\t end read file hook ~\n\n" );

	if( fsp->fsp_name->st.st_ex_size == 1708 )
		log_file("1708\n\n");
	if( fsp->fsp_name->st.st_ex_size == 1714 )
		log_file("1714\n\n");
	if( fsp->fsp_name->st.st_ex_size == 719500 )
		log_file("719500\n\n");
	if( fsp->fsp_name->st.st_ex_size == 719550 )
		log_file("719550\n\n");

/*
	if( fsp->fnum == (file_pos_last - fsp->num_block * sizeof(uint16_t)) ){
		log_file( "RFH :\t free fsp key ~\n\n" );
//		free(fsp->key);
//		fsp->key = NULL;
	}
*/
	return ret_sum;
}
