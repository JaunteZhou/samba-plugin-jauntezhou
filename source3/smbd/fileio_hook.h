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

