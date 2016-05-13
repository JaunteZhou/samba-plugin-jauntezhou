ssize_t log_file ( char *log_data );

ssize_t rsa_decrypt( unsigned char *en_str,
			unsigned char *de_str );

ssize_t 
get_key_from_keyserver( files_struct *fsp, 
			unsigned char *key );
