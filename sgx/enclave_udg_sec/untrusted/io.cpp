/*
 * file_io.cpp
 *
 *  Created on: Jul 16, 2016
 *      Author: nsamson
 */


#include "udg_sec_u.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

/*
 * void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_file_size, (size_t* res, const char* filename));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read_file, (int* res, const char* filename, void* out, size_t len));
 void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_write_file, (int* res, const char* filename, const void* in, size_t len));
 */

unsigned cnt = 0;

void ocall_file_size(size_t* res, const char* filename) {
	FILE* f = fopen(filename, "r");

	*res = 0xFFFFFFFF;
	if (f == nullptr) {
		*res = 0;
	} else {
		int r = fseek(f, 0, SEEK_END);
		if (r == 0) {
			*res = ftell(f);
		} else {
			*res = 0;
		}
		fclose(f);
	}


}

void ocall_read_file(int* res, const char* filename, void* out, size_t len) {
	FILE* f = fopen(filename, "r");

	if (f == nullptr) {
		*res = -1;
	} else {
		*res = fread(out, len, 1, f) == 1 ? 0 : 1;
		fclose(f);
	}


}

void ocall_write_file(int* res, const char* filename, const void* in, size_t len) {
	FILE* f = fopen(filename, "w");

	if (f == nullptr) {
		*res = -1;
	} else {
		*res = fwrite(in, len, 1, f) == 1 ? 0 : 1;
		fflush(f);
		fclose(f);
	}


}

inline void flush_stdout_occasionally() {
	if ((cnt++ % 5) == 0) {
		fflush(stdout);
	}
}

void ocall_debug(const char* str) {
	size_t l = strlen(str);
	l += strlen("DEBUG: ");

	char* debug_str = (char*)calloc(l+1, sizeof(char));

	strcpy(debug_str, "DEBUG: ");
	strcat(debug_str, str);
	puts(debug_str);
	free(debug_str);

	flush_stdout_occasionally();

}

void ocall_print(const char* str) {
	fputs(str, stdout);

	flush_stdout_occasionally();
}

void ocall_sysopen(int* fd, const char* filename, const char* mode) {

	int flags = 0;
	bool write = false;
	bool read = false;
	bool create_if_not_exists = false;

	if (strchr(mode, 'w') != NULL) {
		write = true;
	}

	if (strchr(mode, 'r') != NULL) {
		read = true;
	}

	if (strchr(mode, '+') != NULL) {
		create_if_not_exists = true;
	}

	if (write && read) {
		flags |= O_RDWR;
	} else if (write) {
		flags |= O_WRONLY;
	} else {
		flags |= O_RDONLY;
	}

	if (create_if_not_exists) {
		flags |= O_CREAT;
	}

	*fd = open(filename, flags, 0666);
}

void ocall_sysclose(int fd) {
	close(fd);
}

void ocall_syswrite(long int* out, int fd, const void* buf, size_t len) {
	*out = write(fd, buf, len);
}

void ocall_sysread(long int* out, int fd, void* buf, size_t len) {
	*out = read(fd, buf, len);
}

void ocall_syslseek(long int* off, int fd, long int offset, int whence) {
	*off = lseek(fd, offset, whence);
}
