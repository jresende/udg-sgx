/*
 * io.cpp
 *
 *  Created on: Jul 16, 2016
 *      Author: nsamson
 */

#include "io.hpp"
#include "../udg_sec.h"
#include "../udg_sec_t.h"
#include "intconv.hpp"
#include <sgx_tseal.h>
#include <stdlib.h>
#include <string.h>

using namespace udg;

#define MAX_PUT_SIZE 1024 * 1024

void p(const char* s) {
	ocall_print(s);
}

void d(const char*s) {
#ifndef NDEBUG
	ocall_debug(s);
#else
	(void) s;
#endif
}

io::simple_io udg::io::cout = udg::io::simple_io(p);
io::simple_io udg::io::cdebug = udg::io::simple_io(d);

udg::io::simple_io::simple_io(io_handler handler) {
	this->handler = handler;
}

void udg::io::simple_io::puts(const char* str) {
	this->handler(str);
}

io::simple_io& udg::io::simple_io::operator <<(const std::string& str) {
	*this << str.c_str();

	return *this;
}

io::simple_io& udg::io::simple_io::operator <<(const char* str) {
	this->handler(str);

	return *this;
}

io::simple_io& udg::io::simple_io::operator <<(const uint8_t* str) {
	this->handler((const char*) str);

	return *this;
}

io::simple_io& udg::io::simple_io::operator <<(long long int num) {

	*this << udg::lltostr(num);
	return *this;

}

io::simple_io& udg::io::simple_io::operator <<(long int num) {

	*this << udg::lltostr(num);
	return *this;

}

io::simple_io& udg::io::simple_io::operator <<(int num) {

	*this << udg::lltostr(num);
	return *this;

}


io::simple_io& udg::io::simple_io::operator <<(short num) {

	*this << udg::lltostr(num);
	return *this;

}


io::simple_io& udg::io::simple_io::operator <<(char num) {

	char c[2] = {};
	c[0] = num;
	*this << c;
	return *this;

}

io::simple_io& udg::io::simple_io::operator <<(unsigned long long int num) {

	*this << udg::ulltostr(num);
	return *this;

}

io::simple_io& udg::io::simple_io::operator <<(unsigned long int num) {

	*this << udg::ulltostr(num);
	return *this;

}

io::simple_io& udg::io::simple_io::operator <<(unsigned int num) {

	*this << udg::ulltostr(num);
	return *this;

}

io::simple_io& udg::io::simple_io::operator <<(unsigned short num) {

	*this << udg::ulltostr(num);
	return *this;

}

io::simple_io& udg::io::simple_io::operator <<(unsigned char num) {

	*this << (char) num;
	return *this;

}

io::simple_io& udg::io::simple_io::operator <<(bool b) {
	*this << (b ? "true" : "false");
	return *this;
}

udg::io::DBSession::DBSession(const char* filename, bool create_if_not_exists) {
	int desc;
	ocall_db_open(&desc, filename, create_if_not_exists ? 1 : 0);

	this->db_ref = boost::shared_ptr<int>(new int);
	*db_ref = desc;
}

ssize_t udg::io::DBSession::get(const char* key, char* out, size_t len, bool decrypt) {
	ssize_t out_len;
	ocall_db_get(&out_len, *this->db_ref, key, out, len);
	if (out_len >= 0 && decrypt) {
		char* tmp = (char*) calloc(len, sizeof(char));
		uint32_t mac_len = 0;
		memcpy(tmp, out, out_len);

		sgx_sealed_data_t* sealed_data = reinterpret_cast<sgx_sealed_data_t*>(tmp);
		sgx_status_t stat = sgx_unseal_data(sealed_data, nullptr, &mac_len, (uint8_t*) out, (uint32_t*) &out_len);

		free(tmp);

		if (stat != SGX_SUCCESS) {
			return -1;
		} else {
			return out_len;
		}
	} else if (out_len >= 0 && !decrypt) {
		return out_len;
	} else {
		return out_len;
	}
}

udg::io::DBSession::~DBSession() {
	ocall_db_close(*this->db_ref);
}

void udg::io::DBSession::put(const char* key, const char* value, bool encrypt) {
	if (!encrypt) {
		ocall_db_put(*this->db_ref, key, value);
	} else {
		uint32_t crypt_size = strnlen(value, MAX_PUT_SIZE);
		uint32_t sealed_size = sgx_calc_sealed_data_size(0, crypt_size);

		uint8_t* encrypted_dat = (uint8_t*) calloc(sealed_size + 1, sizeof(uint8_t));
		sgx_seal_data(
				0,
				nullptr,
				crypt_size,
				(const uint8_t*)value,
				sealed_size,
				(sgx_sealed_data_t*) encrypted_dat
				);

		encrypted_dat[sealed_size] = 0;

		this->put(key, value, false);

	}
}

void udg::io::DBSession::del(const char* key) {
	ocall_db_del(*this->db_ref, key);
}

udg::io::file::file(const std::string& name, const std::string& mode) {

	int* fd = new int;
	ocall_sysopen(fd, name.c_str(), mode.c_str());

	if (*fd < 0) {
		throw std::runtime_error("Error while opening file.");
	}

	this->fd = boost::shared_ptr<int>(fd, [](int* x) -> void{ocall_sysclose(*x);});

}

ssize_t udg::io::file::write(const void* data, size_t len) {

	long int written;
	ocall_syswrite(&written, *this->fd, data, len);

	return written;

}

ssize_t udg::io::file::read(void* buf, size_t len) {
	long int read;
	ocall_sysread(&read, *this->fd, buf, len);

	return read;
}

long int udg::io::file::seek(long int offset, int whence) {

	long int out;
	ocall_syslseek(&out, *this->fd, offset, whence);

	return out;

}
