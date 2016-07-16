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

/*
 * void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_file_size, (size_t* res, const char* filename));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read_file, (int* res, const char* filename, void* out, size_t len));
 void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_write_file, (int* res, const char* filename, const void* in, size_t len));
 */

void ocall_file_size(size_t* res, const char* filename) {
	FILE* f = fopen(filename, "r");

	if (f == nullptr) {
		*res = 0;
	} else {
		int r = fseek(f, 0, SEEK_END);
		if (r == 0) {
			*res = ftell(f);
		} else {
			*res = 0;
		}
	}

	fclose(f);
}

void ocall_read_file(int* res, const char* filename, void* out, size_t len) {
	FILE* f = fopen(filename, "r");

	if (f == nullptr) {
		*res = -1;
	} else {
		*res = fread(out, len, 1, f) == 1 ? 0 : 1;
	}

	fclose(f);
}

void ocall_write_file(int* res, const char* filename, const void* in, size_t len) {
	FILE* f = fopen(filename, "w");

	if (f == nullptr) {
		*res = -1;
	} else {
		*res = fwrite(in, len, 1, f) == 1 ? 0 : 1;
	}

	fflush(f);
	fclose(f);
}

void ocall_debug(const char* str) {
	size_t l = strlen(str);
	l += strlen("DEBUG: ");

	char* debug_str = (char*)calloc(l+1, sizeof(char));

	strcpy(debug_str, "DEBUG: ");
	strcat(debug_str, str);
	puts(debug_str);
	free(debug_str);
}

void ocall_print(const char* str) {
	puts(str);
}
