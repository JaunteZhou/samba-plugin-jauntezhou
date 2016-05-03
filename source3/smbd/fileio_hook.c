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

#include "fileio_hook.h"

#include <openssl/aes.h>  
#include <openssl/rand.h>  

#define USER_KEY_SIZE 16

#define BLOCK_SIZE 128

int log_file (char *fn, char *log_data) {
	FILE *fp;
	// test
	fp = fopen(fn,"wb");
	if (fp == NULL){
		//DEBUG("Open Key TXT ERROR !!!");
		return 0;
	}
	fwrite(log_data, 1, sizeof(log_data), fp);
	fclose(fp);
	// test end
	return 1;
}

/////////////////////////////////////////////////////////////////////////////////////////////////
/*
static int fd_write = -1;
static int fd_read = -1;

struct write_cache {
	off_t file_size;	//文件大小
	off_t offset;		//缓冲区开始对应的文件偏移量
	size_t alloc_size;	//缓冲区大小
	size_t data_size;	//当前缓冲区中数据大小
	char *data;			//缓冲区数据
};
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
	size_t		num_block;


	//128bits key.
	unsigned char   rkey[USER_KEY_SIZE] = "jauntezhou010502";
	//Internal key.  
	AES_KEY         en_key;
	int 		num_bits = 0;

	//Set Entrypt Key
	num_bits = 8 * sizeof(rkey);
	AES_set_encrypt_key(rkey, num_bits, &en_key);

	log_file("/home/jauntezhou/Desktop/wfh_f0.txt","write_file_hook Start !\n");

	char *plaint_data;
	char *encrypted_data;
	char log_buf;
/*
	file_pos_last = pos;
	file_n_temp = n;
*/
	num_block = (file_pos_src/* + 1*/) / BLOCK_SIZE;
	file_pos_last = file_pos_src + (num_block+1) * sizeof(uint8_t)/*num_block * (BLOCK_SIZE + sizeof(uint8_t)) - 1*/;
/*
	log_buf = (char *)malloc(128);
	char *c1 = "file_pos_src : ";
	char *c2 = "file_pos_last : ";
	memset( log_buf, 0, 128);
	sprintf( log_buf, "%s : %d", c1, file_pos_src );
	sprintf( log_buf + strlen(log_buf), "%s : %d", c2, file_pos_last );
	log_file("/home/jauntezhou/Desktop/wfh_pooos.txt", log_buf);
	free(log_buf);

	printf("file_pos_src : %d\n", file_pos_src);
	printf("file_pos_last : %d\n", file_pos_last);
	scanf("%c", &log_buf);
*/
	if( file_pos_src == -1 ) {
		file_pos_last = -1;
		log_file("/home/jauntezhou/Desktop/wfh_f101.txt","write_file_hook Start read last data!\n");
	} else if ( file_pos_src == 0 ){
		file_pos_last = 0;
		log_file("/home/jauntezhou/Desktop/wfh_f100.txt","write_file_hook Start read last data!\n");
	}

	if ( (file_pos_src/*+1*/) % BLOCK_SIZE > 0 ){
		if( file_pos_last == -1)
			log_file("/home/jauntezhou/Desktop/wfh_f11.txt","write_file_hook Start read last data!\n");
		log_file("/home/jauntezhou/Desktop/wfh_f1.txt","write_file_hook Start read last data!\n");

		ret = SMB_VFS_PREAD(fsp, &file_n_last, sizeof(uint8_t), file_pos_last/*+1*/);
		if (ret != sizeof(uint8_t)){
			log_file("/home/jauntezhou/Desktop/wfh_e0.txt","write_file_hook Error: read last length wrong !\n");
			return -1;
		}
		
		file_n_temp = ((file_n_last + file_n_src) > BLOCK_SIZE) ? BLOCK_SIZE : (uint8_t)(file_n_last + file_n_src);

		//prepare first plaint data = last_n_data + part_of_new_data 
		plaint_data = (char *)malloc(file_n_temp);
		memset(plaint_data, 0, file_n_temp);

		encrypted_data = (char *)malloc(file_n_last);
		memset(encrypted_data, 0, file_n_last);
		
		//read last_n_data
		ret = SMB_VFS_PREAD(fsp, encrypted_data, file_n_last, file_pos_last + sizeof(uint8_t)/*+1*/);
		if ( ret != file_n_last ){
			log_file("/home/jauntezhou/Desktop/wfh_e1.txt","write_file_hook Error: read last data wrong !\n");
			return -1;
		}

		//decrypted last_n_data to plaint_data
		AES_KEY         de_key;
		num_bits = 8 * sizeof(rkey);
		AES_set_decrypt_key(rkey, num_bits, &de_key);
//		AES_decrypt( encrypted_data, plaint_data, &de_key);
		memcpy(plaint_data, encrypted_data, file_n_last);
		free(encrypted_data);

		//copy part_of_new_data to plaint_data
		memcpy((plaint_data + file_n_last), data, file_n_temp - file_n_last);


		encrypted_data = (char *)malloc(file_n_temp + sizeof(uint8_t));
		memcpy(encrypted_data, &file_n_temp, sizeof(uint8_t));
//		AES_encrypt(plaint_data, (void *)(encrypted_data+sizeof(uint8_t)), &en_key);
		memcpy( encrypted_data + sizeof(uint8_t), plaint_data, file_n_temp);


		ret = vfs_pwrite_data(NULL, fsp, encrypted_data, file_n_temp + sizeof(uint8_t), file_pos_last/*+1*/);
		if( ret == -1 || ret != file_n_temp+sizeof(uint8_t)) {
			//DEGUB("write 11 error!\n");
			return -1;
		}
		
		log_file("/home/jauntezhou/Desktop/wfh_f2.txt","write_file_hook End read last data !\n");

		ret_sum += (file_n_temp - file_n_last);
		file_n_rest -= (file_n_temp - file_n_last);
		file_pos_last += file_n_temp + sizeof(uint8_t);

		free(plaint_data);
		free(encrypted_data);
	}

	while ( file_n_rest > 0 ) {
		log_file("/home/jauntezhou/Desktop/wfh_f3.txt","write_file_hook Start write data !\n");

		if ( file_n_rest >= BLOCK_SIZE ) {
			file_n_temp = BLOCK_SIZE;
		} else {
			file_n_temp = (uint8_t)file_n_rest;
		}

		//Init Buffer
		plaint_data = (char *)malloc(file_n_temp);
		memset(plaint_data, 0, file_n_temp);
		memcpy(plaint_data, (data + ret_sum), file_n_temp);

		encrypted_data = (char *)malloc(file_n_temp + sizeof(uint8_t));
		memset(encrypted_data, 0, file_n_temp + sizeof(uint8_t));
		memcpy(encrypted_data, &file_n_temp, sizeof(uint8_t));

		memcpy(encrypted_data + sizeof(uint8_t), plaint_data, file_n_temp);
//		AES_encrypt(plaint_data, (encrypted_data+sizeof(uint8_t)), &en_key);

		log_file("/home/jauntezhou/Desktop/wfh_f4.txt","write_file_hook Start write to cashe !\n");

		/*step4: 数据存盘 */
		if (file_pos_last == -1) {
			log_file("/home/jauntezhou/Desktop/wfh_f5.txt","write_file_hook Start write from beginning !\n");
			//从文件开头写
    			ret = vfs_write_data(NULL, fsp, encrypted_data, file_n_temp + sizeof(uint8_t));
		} else {
			log_file("/home/jauntezhou/Desktop/wfh_f6.txt","write_file_hook Start write from middle !\n");
    			//从偏移量‘pos’开始写
			ret = vfs_pwrite_data(NULL, fsp, encrypted_data, file_n_temp + sizeof(uint8_t), file_pos_last);
		}
	
		//xie ru cuo wu huo xie ru bu wanzheng
		if (ret == -1) {
			log_file("/home/jauntezhou/Desktop/wfh_e3.txt","write_file_hook Error: write error !\n");
			return -1;
		} else if ( ret != file_n_temp +sizeof(uint8_t) ) {
			log_file("/home/jauntezhou/Desktop/wfh_e4.txt","write_file_hook Error: write error !\n");
			return -1;
		}


		ret_sum += ret - sizeof(uint8_t);
		file_n_rest -= (ret - sizeof(uint8_t));
		file_pos_last += ret;

		log_file("/home/jauntezhou/Desktop/wfh_f7.txt","write_file_hook Start write a part !\n");

		free(plaint_data);
		free(encrypted_data);	
	}
	log_file("/home/jauntezhou/Desktop/wfh_f8.txt","write_file_hook End !\n");
	
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
	unsigned char   rkey[USER_KEY_SIZE] = "jauntezhou010502";
	//Internal key.  
	AES_KEY         de_key; 

	//Decrypt Data
	num_bits = 8 * USER_KEY_SIZE;  
	AES_set_decrypt_key(rkey, num_bits, &de_key); 

	//Buffer for Encrypted Data
	char *encrypted_data;
	char *decrypted_data;


	log_file("/home/jauntezhou/Desktop/rfh_f0.txt", "start read_file_hook ~\n");
	
	num_block_rdd = (file_pos_src) / BLOCK_SIZE;
	file_pos_last = num_block_rdd * (BLOCK_SIZE + sizeof(uint8_t));

//	file_n_temp = n;
	
//	file_pos_last = pos;
	

//	ret = SMB_VFS_PREAD(fsp, /*encrypted_*/data, file_n_temp, file_pos_last/*+sizeof(uint8_t)*/);
//	return ret;


	while ( file_n_rest > 0 ) {
		log_file("/home/jauntezhou/Desktop/rfh_f1.txt", "start write ~\n");

//		file_n_temp = file_n_rest > BLOCK_SIZE ? BLOCK_SIZE : file_n_rest;


		//Read Encrypted Data
		ret = SMB_VFS_PREAD(fsp, &file_n_temp, sizeof(uint8_t), file_pos_last);
		if ( ret != sizeof(uint8_t) ){
			log_file("/home/jauntezhou/Desktop/rfh_e0.txt", "read error: cannot read next length !~\n");
			return -1;
		}
		if ( file_n_temp > file_n_rest && num_block_rding ){
			log_file("/home/jauntezhou/Desktop/rfh_e1.txt", "read error: read more length than need !~\n");
			break;
		}

		//Init Buffer
		encrypted_data = (char *)malloc(file_n_temp);
		memset(encrypted_data, 0, file_n_temp);

		decrypted_data = (char *)malloc(file_n_temp);
		memset(decrypted_data, 0, file_n_temp);


		log_file("/home/jauntezhou/Desktop/rfh_f2.txt", "start PREAD ~\n");

		//Read Encrypted Data
		ret = SMB_VFS_PREAD(fsp, encrypted_data, file_n_temp, file_pos_last + sizeof(uint8_t));

		if ( ret != file_n_temp ) {
			log_file("/home/jauntezhou/Desktop/rfh_e2.txt", "PREAD Error : not enough~\n");
			free(encrypted_data);
			free(decrypted_data);
			continue;
		}
		if ( ret == -1 ){
			log_file("/home/jauntezhou/Desktop/rfh_e3.txt", "PREAD Error : none ~\n");
			free(encrypted_data);
			free(decrypted_data);
			return -1;
		}

		log_file("/home/jauntezhou/Desktop/rfh_f3.txt", "start decrypted ~\n");
		log_file("/home/jauntezhou/Desktop/data_encrypted.txt", encrypted_data);

/*
		AES_decrypt(encrypted_data, decrypted_data, &de_key);
		//memcpy(data+ret_sum, decrypted_data, ret);
*/
		memcpy((data+ret_sum), /*de*/encrypted_data, file_n_temp);

		ret_sum += ret;
		file_pos_last += ret + sizeof(uint8_t);
		file_n_rest -= (ret + sizeof(uint8_t));

		num_block_rding += 1;

		free(encrypted_data);
		free(decrypted_data);
	}

	fsp->fnum -= num_block_rding;
	log_file("/home/jauntezhou/Desktop/rfh_f4.txt", "end read file hook ~\n");

	return ret_sum;
}
