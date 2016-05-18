//ssize_t log_file ( char *log_data );
ssize_t
encrypt_hook( char *cipher_data, 
		char *plain_data,
		size_t n,
		unsigned char *rkey );

ssize_t
decrypt_hook( char *plain_data,
		char *cipher_data, 
		size_t n,
		unsigned char *rkey );

ssize_t 
write_file_hook(files_struct *fsp,
		const char *data,
		size_t n,
		off_t pos);

ssize_t 
read_file_hook(files_struct *fsp,
		char *data,
		size_t n,
		off_t pos);

