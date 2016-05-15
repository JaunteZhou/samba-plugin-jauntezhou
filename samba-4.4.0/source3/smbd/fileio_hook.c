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

#define BLOCK_SIZE 	32768
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
	size_t		num_en_block = 0;
	size_t		file_n_rest = n;
	size_t	 	file_n_src = n;
	uint16_t	file_n_last = 0;
	
	off_t 		file_pos_src = pos;
	off_t 		file_pos_last;
	size_t		num_block_wtd;
	size_t		num_block_wting = 0;


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

	char *encrypted_data;
	char log_buf;

	num_block_wtd = file_pos_src / BLOCK_SIZE;
	file_pos_last = num_block_wtd * ( BLOCK_SIZE + sizeof(uint16_t) );

	if( file_pos_src == -1 ) {
		file_pos_last = -1;
		log_file( "WFH :\t write_file_hook Start ! pos == -1\n\n" );
	} else if ( file_pos_src == 0 ){
		file_pos_last = 0;
		log_file( "WFH :\t write_file_hook Start ! pos == 0\n\n" );
	}

	if ( file_pos_src % BLOCK_SIZE > 0 ){
		if( file_pos_last == -1)
			log_file( "WFH :\t write_file_hook Start read last data, pos == -1 !\n\n" );
		else
			log_file( "WFH :\t write_file_hook Start read last data!, pos != -1 !\n\n" );

		size_t wtd_data_len = 0;
		ret = SMB_VFS_PREAD(fsp, &wtd_data_len, sizeof(uint16_t), file_pos_last);
		if (ret != sizeof(uint16_t)){
			log_file( "WFH ERROR :\t read last length wrong !\n\n" );
			return -1;
		}
		

		file_n_temp = ((wtd_data_len + file_n_src) > BLOCK_SIZE) ? BLOCK_SIZE : (uint16_t)(wtd_data_len + file_n_src);
		ret = vfs_pwrite_data(NULL, fsp, (char *)&file_n_temp, sizeof(uint16_t), file_pos_last);

		
		size_t wtd_buf_len = ( wtd_data_len / EN_BLOCK_SIZE ) * EN_BLOCK_SIZE;
		file_pos_last += sizeof(uint16_t) + wtd_buf_len;
		file_n_temp -= wtd_buf_len;
		wtd_data_len -= wtd_buf_len;

		num_en_block = file_n_temp % EN_BLOCK_SIZE == 0 ? 
				file_n_temp / EN_BLOCK_SIZE : 
				file_n_temp / EN_BLOCK_SIZE + 1;
		wt_buf_len = num_en_block * EN_BLOCK_SIZE;

		//prepare first plaint data = last_n_data + part_of_new_data 
		char *plaint_data;
		plaint_data = (char *)malloc(wt_buf_len);
		memset(plaint_data, 0, wt_buf_len);

		encrypted_data = (char *)malloc(wt_buf_len);
		memset(encrypted_data, 0, wt_buf_len);
		
		//read last_n_data
		ret = SMB_VFS_PREAD(fsp, encrypted_data, EN_BLOCK_SIZE, file_pos_last);
		if ( ret != EN_BLOCK_SIZE ){
			log_file( "WFH ERROR :\t read last data wrong !\n\n" );
			return -1;
		}

		//decrypted last_n_data to plaint_data
		AES_KEY         de_key;
		num_bits = 8 * KEY_SIZE;
		AES_set_decrypt_key(rkey, num_bits, &de_key);
		AES_decrypt( encrypted_data, plaint_data, &de_key);

		//copy part_of_new_data to plaint_data
		memcpy( ( plaint_data + wtd_data_len ), data, file_n_temp - wtd_data_len );


//		encrypted_data = (char *)malloc(BLOCK_SIZE + sizeof(uint16_t));
//		memcpy(encrypted_data, &file_n_temp, sizeof(uint16_t));
		en_sum = 0;
		while(num_en_block){
			AES_encrypt( (plaint_data+en_sum), (encrypted_data+en_sum), &en_key );
			en_sum += EN_BLOCK_SIZE;
			num_en_block -= 1;
		}

		ret = vfs_pwrite_data(NULL, fsp, encrypted_data, wt_buf_len, file_pos_last);
		if( ret == -1 || ret != wt_buf_len ) {
			log_file("write 11 error!\n\n");
			return -1;
		}
		
		log_file( "WFH :\t End read last data !\n\n" );

		ret_sum += (file_n_temp - wtd_data_len);
		file_n_rest -= (file_n_temp - wtd_data_len);
		file_pos_last += wt_buf_len;

		free(plaint_data);
		free(encrypted_data);
	}

	while ( file_n_rest > 0 ) {
		//log_file( "WFH :\t write_file_hook Start write data !\n\n" );

		if ( file_n_rest >= BLOCK_SIZE ) {
			file_n_temp = BLOCK_SIZE;
		} else {
			file_n_temp = (uint16_t)file_n_rest;
			log_file("not length to BLOCK_SIZE\n\n");
		}
		num_en_block = file_n_temp % EN_BLOCK_SIZE == 0 ? 
				file_n_temp / EN_BLOCK_SIZE : 
				file_n_temp / EN_BLOCK_SIZE + 1;
		wt_buf_len = num_en_block * EN_BLOCK_SIZE;

		//Init Buffer
		encrypted_data = (char *)malloc(wt_buf_len + sizeof(uint16_t));
		memset(encrypted_data, 0, wt_buf_len + sizeof(uint16_t));
		memcpy(encrypted_data, &file_n_temp, sizeof(uint16_t));

		en_sum = 0;
		while(num_en_block){
			AES_encrypt( (data+ret_sum+en_sum), (encrypted_data+sizeof(uint16_t)+en_sum), &en_key);
			en_sum += EN_BLOCK_SIZE;
			num_en_block -= 1;
		}
		log_file( "WFH :\t Start write to cashe !\n\n" );

		/*step4: 数据存盘 */
		if (file_pos_last == -1) {
			log_file( "WFH :\t Start write from beginning !\n\n" );
			//从文件开头写
    			ret = vfs_write_data(NULL, fsp, encrypted_data, wt_buf_len + sizeof(uint16_t));
		} else {
			log_file( "WFH :\t Start write from middle !\n\n" );
    			//从偏移量‘pos’开始写
			ret = vfs_pwrite_data(NULL, fsp, encrypted_data, wt_buf_len + sizeof(uint16_t), file_pos_last);
		}
		log_file( "WFH :\t Start write to cashe End !\n\n" );

		//xie ru cuo wu huo xie ru bu wanzheng
		if (ret == -1) {
			log_file( "WFH ERROR :\t write error !\n\n" );
			return -1;
		} else if ( ret != wt_buf_len + sizeof(uint16_t) ) {
			log_file( "WFH ERROR :\t write error !\n\n" );
			return -1;
		}


		ret_sum += file_n_temp;
		file_n_rest -= file_n_temp;
		file_pos_last += ret;

		//log_file( "WFH :\t Start write a part !\n\n" );

		num_block_wting += 1;

		//free(plaint_data);
		free(encrypted_data);	
	}

	log_file( "WFH :\t write_file_hook End !\n\n" );

	fsp->num_block += num_block_wting;
	if( fsp->fsp_name->st.st_ex_size == 1708 )
		log_file("1708\n\n");
	if( fsp->fsp_name->st.st_ex_size == 1714 )
		log_file("1714\n\n");
	if( fsp->fsp_name->st.st_ex_size == 719500 )
		log_file("719500\n\n");
	if( fsp->fsp_name->st.st_ex_size == 719550 )
		log_file("719550\n\n");

/*	if( fsp->fnum + fsp->num_block * sizeof(uint16_t) == file_pos_last ){
		log_file( "WFH :\t free key !!!!!\n\n" );
		//free(fsp->key);
		//fsp->key = NULL;
	}
*/	
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
	uint16_t	file_n_temp = 0;
	uint16_t	rd_buf_len = 0;
	size_t		num_de_block = 0;
	size_t		file_n_rest = n;
	size_t	 	file_n_src = n;
	size_t	 	num_block_rdd = 0;
	size_t	 	num_block_rding = 0;
	uint16_t	file_n_last = 0;

	off_t	 	file_pos_src = pos;
	off_t	 	file_pos_last;

	size_t		black_len = 0;

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

	//Buffer for Encrypted Data
	char *encrypted_data;
	char *decrypted_data;


	log_file( "RFH :\t start read_file_hook ~\n\n" );
	
	num_block_rdd = file_pos_src / BLOCK_SIZE;		// + sizeof(uint16_t)
	file_pos_last = num_block_rdd * (BLOCK_SIZE + sizeof(uint16_t));

	if ( file_pos_src % BLOCK_SIZE > 0 ){
		log_file( "RFH :\t start read last data ! ~\n\n" );
		ret = SMB_VFS_PREAD(fsp, &file_n_temp, sizeof(uint16_t), file_pos_last);
		if ( ret != sizeof(uint16_t) ){
			log_file( "RFH ERROR :\t pread cannot read next length !~\n\n" );
			return -1;
		}

		file_pos_last += sizeof(uint16_t);
		//file_n_rest -= sizeof(uint16_t);

		size_t rdd_data_len = ( file_pos_src % BLOCK_SIZE );
		size_t rdd_block_len = rdd_data_len / EN_BLOCK_SIZE * EN_BLOCK_SIZE;
		file_pos_last += rdd_block_len;
		file_n_temp -= rdd_block_len;
		rdd_data_len -= rdd_block_len;

		num_de_block = file_n_temp % EN_BLOCK_SIZE == 0 ? 
				file_n_temp / EN_BLOCK_SIZE : 
				file_n_temp / EN_BLOCK_SIZE + 1;
		rd_buf_len = num_de_block * EN_BLOCK_SIZE;

		//Init Buffer
		encrypted_data = (char *)malloc(rd_buf_len);
		memset(encrypted_data, 0, rd_buf_len);
		decrypted_data = (char *)malloc(rd_buf_len);
		memset(decrypted_data, 0, rd_buf_len);

		ret = SMB_VFS_PREAD(fsp, encrypted_data, rd_buf_len, file_pos_last);
		if ( ret != rd_buf_len ) {
			log_file( "PREAD ERROR :\t pread not enough~\n\n" );
			free(encrypted_data);
			free(decrypted_data);
			return -1;
		}
		if ( ret == -1 ){
			log_file( "PREAD ERROR :\t pread none ~\n\n" );
			free(encrypted_data);
			free(decrypted_data);
			return -1;
		}

		de_sum = 0;
		while(num_de_block){
			AES_decrypt( (encrypted_data+de_sum), (decrypted_data+de_sum), &de_key );
			de_sum += EN_BLOCK_SIZE;
			num_de_block -= 1;
		}
		memcpy( data + ret_sum, decrypted_data + rdd_data_len, file_n_temp - rdd_data_len );

		file_pos_last += rd_buf_len;
		file_n_rest -= (file_n_temp - rdd_data_len);
		ret_sum += (file_n_temp - rdd_data_len);

		//num_block_rding += 1;

		free(encrypted_data);
		free(decrypted_data);
	}

	while ( file_n_rest > 0 ) {
		log_file( "RFH :\t start read ~\n\n" );

		//Read Encrypted Data
		ret = SMB_VFS_PREAD( fsp, &file_n_temp, sizeof(uint16_t), file_pos_last );
		if ( ret != sizeof(uint16_t) ){
			log_file( "RFH ERROR :\t cannot read next length !~\n\n" );
			return -1;
		}

		file_pos_last += sizeof(uint16_t);
		file_n_rest -= sizeof(uint16_t);

		if ( file_n_temp > file_n_rest ){
			file_n_temp = file_n_rest;
			log_file( "RFH ERROR :\t mainread read more length than need !~\n\n" );
			//break;
		}
		num_de_block = file_n_temp % EN_BLOCK_SIZE == 0 ? 
				file_n_temp / EN_BLOCK_SIZE : 
				file_n_temp / EN_BLOCK_SIZE + 1;
		rd_buf_len = num_de_block * EN_BLOCK_SIZE;

		//Init Buffer
		encrypted_data = (char *)malloc(rd_buf_len);		//!!!!!!!!!!!!!!!!!!!sizeof(uint16_t)
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
			//file_pos_last -= sizeof(uint16_t);
			//file_n_rest += sizeof(uint16_t);
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
		memcpy(data+ret_sum, decrypted_data, file_n_temp);
		
		file_pos_last += (file_n_temp);
		file_n_rest -= (file_n_temp);

		ret_sum += (file_n_temp);

		num_block_rding += 1;

		free(encrypted_data);
		free(decrypted_data);
	}
	log_file( "RFH :\t end read file hook ~\n\n" );
	fsp->num_block += num_block_rding;

	fsp->fsp_name->st.st_ex_size -= num_block_rding * sizeof(uint16_t);

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
