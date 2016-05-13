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

#define BLOCK_SIZE 16
/*
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
*/
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
	uint8_t 	file_n_temp = 0;
	size_t		file_n_rest = n;
	size_t	 	file_n_src = n;
	uint8_t	 	file_n_last = 0;
	
	off_t 		file_pos_src = pos;
	off_t 		file_pos_last;
	size_t		num_block_wtd;
	size_t		num_block_wting = 0;


	//128bits key.
	unsigned char   rkey[KEY_SIZE] = "jauntezhou010502";
	//unsigned char *rkey;
	//rkey = (unsigned char *)malloc(KEY_SIZE);
	//ret = get_key_from_keyserver( fsp, rkey );

	// get key when begin write file
/*	if( pos == 0 || fsp->key == NULL ){
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
*/

	//Internal key.  
	AES_KEY         en_key;
	int 		num_bits = 0;

	//Set Entrypt Key
	num_bits = 8 * KEY_SIZE;
	AES_set_encrypt_key(rkey, num_bits, &en_key);

	log_file( "WFH :\t write_file_hook Start !\n\n" );

	char *plaint_data;
	char *encrypted_data;
	char log_buf;

	num_block_wtd = (file_pos_src/* + 1*/) / BLOCK_SIZE;
	file_pos_last = file_pos_src + (num_block_wtd+1) * sizeof(uint8_t)/*num_block_wtd * (BLOCK_SIZE + sizeof(uint8_t)) - 1*/;

	if( file_pos_src == -1 ) {
		file_pos_last = -1;
		log_file( "WFH :\t write_file_hook Start ! pos == -1\n\n" );
	} else if ( file_pos_src == 0 ){
		file_pos_last = 0;
		log_file( "WFH :\t write_file_hook Start ! pos == 0\n\n" );
	}

	if ( (file_pos_src) % BLOCK_SIZE > 0 ){
		if( file_pos_last == -1)
			log_file( "WFH :\t write_file_hook Start read last data, pos == -1 !\n\n" );
		else
			log_file( "WFH :\t write_file_hook Start read last data!, pos != -1 !\n\n" );

		ret = SMB_VFS_PREAD(fsp, &file_n_last, sizeof(uint8_t), file_pos_last/*+1*/);
		if (ret != sizeof(uint8_t)){
			log_file( "WFH ERROR :\t read last length wrong !\n\n" );
			return -1;
		}
		
		file_n_temp = ((file_n_last + file_n_src) > BLOCK_SIZE) ? BLOCK_SIZE : (uint8_t)(file_n_last + file_n_src);

		//prepare first plaint data = last_n_data + part_of_new_data 
		plaint_data = (char *)malloc(BLOCK_SIZE);
		memset(plaint_data, 0, BLOCK_SIZE);

		encrypted_data = (char *)malloc(BLOCK_SIZE);
		memset(encrypted_data, 0, BLOCK_SIZE);
		
		//read last_n_data
		ret = SMB_VFS_PREAD(fsp, encrypted_data, BLOCK_SIZE, file_pos_last + sizeof(uint8_t)/*+1*/);
		if ( ret != BLOCK_SIZE ){
			log_file( "WFH ERROR :\t read last data wrong !\n\n" );
			return -1;
		}

		//decrypted last_n_data to plaint_data
		AES_KEY         de_key;
		num_bits = 8 * KEY_SIZE;
		AES_set_decrypt_key(rkey, num_bits, &de_key);
		AES_decrypt( encrypted_data, plaint_data, &de_key);
//		memcpy(plaint_data, encrypted_data, file_n_last);
		free(encrypted_data);

		//copy part_of_new_data to plaint_data
		memcpy((plaint_data + file_n_last), data, file_n_temp - file_n_last);


		encrypted_data = (char *)malloc(BLOCK_SIZE + sizeof(uint8_t));
		memcpy(encrypted_data, &file_n_temp, sizeof(uint8_t));
		AES_encrypt(plaint_data, (void *)(encrypted_data+sizeof(uint8_t)), &en_key);
//		memcpy( encrypted_data + sizeof(uint8_t), plaint_data, file_n_temp);


		ret = vfs_pwrite_data(NULL, fsp, encrypted_data, BLOCK_SIZE + sizeof(uint8_t), file_pos_last/*+1*/);
		if( ret == -1 || ret != BLOCK_SIZE+sizeof(uint8_t)) {
			//DEGUB("write 11 error!\n\n");
			return -1;
		}
		
		log_file( "WFH :\t End read last data !\n\n" );

		ret_sum += (file_n_temp - file_n_last);
		file_n_rest -= (file_n_temp - file_n_last);
		file_pos_last += BLOCK_SIZE + sizeof(uint8_t);

		free(plaint_data);
		free(encrypted_data);
	}




	while ( file_n_rest > 0 ) {
		log_file( "WFH :\t write_file_hook Start write data !\n\n" );

		if ( file_n_rest >= BLOCK_SIZE ) {
			file_n_temp = BLOCK_SIZE;
		} else {
			file_n_temp = (uint8_t)file_n_rest;
		}

		//Init Buffer
		plaint_data = (char *)malloc(BLOCK_SIZE);
		memset(plaint_data, 0, BLOCK_SIZE);
		memcpy(plaint_data, (data + ret_sum), file_n_temp);

		encrypted_data = (char *)malloc(BLOCK_SIZE + sizeof(uint8_t));
		memset(encrypted_data, 0, BLOCK_SIZE + sizeof(uint8_t));
		memcpy(encrypted_data, &file_n_temp, sizeof(uint8_t));

//		memcpy(encrypted_data + sizeof(uint8_t), plaint_data, file_n_temp);
		AES_encrypt(plaint_data, (encrypted_data+sizeof(uint8_t)), &en_key);

		log_file( "WFH :\t Start write to cashe !\n\n" );

		/*step4: 数据存盘 */
		if (file_pos_last == -1) {
			log_file( "WFH :\t Start write from beginning !\n\n" );
			//从文件开头写
    			ret = vfs_write_data(NULL, fsp, encrypted_data, BLOCK_SIZE + sizeof(uint8_t));
		} else {
			log_file( "WFH :\t Start write from middle !\n\n" );
    			//从偏移量‘pos’开始写
			ret = vfs_pwrite_data(NULL, fsp, encrypted_data, BLOCK_SIZE + sizeof(uint8_t), file_pos_last);
		}
	
		//xie ru cuo wu huo xie ru bu wanzheng
		if (ret == -1) {
			log_file( "WFH ERROR :\t write error !\n\n" );
			return -1;
		} else if ( ret != BLOCK_SIZE +sizeof(uint8_t) ) {
			log_file( "WFH ERROR :\t write error !\n\n" );
			return -1;
		}


		ret_sum += file_n_temp;
		file_n_rest -= file_n_temp;
		file_pos_last += ret;

		log_file( "WFH :\t Start write a part !\n\n" );

		num_block_wting += 1;

		free(plaint_data);
		free(encrypted_data);	
	}

	log_file( "WFH :\t write_file_hook End !\n\n" );

	fsp->num_block += num_block_wting;
	if( fsp->fnum + fsp->num_block == file_pos_last ){
		log_file( "WFH :\t free key !!!!!\n\n" );
		//free(fsp->key);
		//fsp->key = NULL;
	}
	
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
	uint8_t	 	file_n_temp = 0;
	size_t		file_n_rest = n;
	size_t	 	file_n_src = n;
	size_t	 	num_block_rdd = 0;
	size_t	 	num_block_rding = 0;
//	uint8_t	 	file_n_last = 0;

	off_t	 	file_pos_src = pos;
	off_t	 	file_pos_last;


	int num_bits = 0;
	//128bits en_key.  
	unsigned char   rkey[KEY_SIZE] = "jauntezhou010502";
	//unsigned char *rkey;
	//rkey = (unsigned char *)malloc(KEY_SIZE);
	//ret = get_key_from_keyserver( fsp, rkey );

	// get key when begin write file
/*	if( pos == 0 || fsp->key == NULL ){
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
*/
	//Internal key.  
	AES_KEY         de_key; 

	//Decrypt Data
	num_bits = 8 * KEY_SIZE;  
	AES_set_decrypt_key(rkey, num_bits, &de_key); 

	//Buffer for Encrypted Data
	char *encrypted_data;
	char *decrypted_data;


	log_file( "RFH :\t start read_file_hook ~\n\n" );
	
	num_block_rdd = (file_pos_src) / BLOCK_SIZE;
	file_pos_last = num_block_rdd * (BLOCK_SIZE + sizeof(uint8_t));

	while ( file_n_rest > 0 ) {
		log_file( "RFH :\t start read ~\n\n" );

		//Read Encrypted Data
		ret = SMB_VFS_PREAD(fsp, &file_n_temp, sizeof(uint8_t), file_pos_last);
		if ( ret != sizeof(uint8_t) ){
			log_file( "RFH ERROR :\t cannot read next length !~\n\n" );
			return -1;
		}
		if ( file_n_temp > file_n_rest ){
			log_file( "RFH ERROR :\t read more length than need !~\n\n" );
			break;
		}

		//Init Buffer
		encrypted_data = (char *)malloc(BLOCK_SIZE);
		memset(encrypted_data, 0, BLOCK_SIZE);

		decrypted_data = (char *)malloc(BLOCK_SIZE);
		memset(decrypted_data, 0, BLOCK_SIZE);


		log_file( "RFH :\t start PREAD ~\n\n" );

		//Read Encrypted Data
		ret = SMB_VFS_PREAD(fsp, encrypted_data, BLOCK_SIZE, file_pos_last + sizeof(uint8_t));

		if ( ret != BLOCK_SIZE ) {
			log_file( "PREAD ERROR :\t not enough~\n\n" );
			free(encrypted_data);
			free(decrypted_data);
			continue;
		}
		if ( ret == -1 ){
			log_file( "PREAD ERROR :\t none ~\n\n" );
			free(encrypted_data);
			free(decrypted_data);
			return -1;
		}

		log_file( "RFH :\t start decrypted ~\n\n" );
		log_file( encrypted_data );


		AES_decrypt(encrypted_data, decrypted_data, &de_key);
		memcpy(data+ret_sum, decrypted_data, file_n_temp);

//		memcpy((data+ret_sum), /*de*/encrypted_data, file_n_temp);

		ret_sum += file_n_temp;
		file_pos_last += BLOCK_SIZE + sizeof(uint8_t);
		file_n_rest -= (BLOCK_SIZE + sizeof(uint8_t));

		num_block_rding += 1;

		free(encrypted_data);
		free(decrypted_data);
	}

	fsp->num_block += num_block_rding;
	fsp->fnum -= num_block_rding;
	log_file( "RFH :\t end read file hook ~\n\n" );

	if( fsp->fnum == (file_pos_last - num_block_rding) ){
		log_file( "RFH :\t free fsp key ~\n\n" );
		free(fsp->key);
		fsp->key = NULL;
	}

	return ret_sum;
}
