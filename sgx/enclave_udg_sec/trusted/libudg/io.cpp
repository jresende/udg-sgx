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

using namespace udg;

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

}

io::simple_io& udg::io::simple_io::operator <<(long int num) {

	*this << udg::lltostr(num);

}

io::simple_io& udg::io::simple_io::operator <<(int num) {

	*this << udg::lltostr(num);

}


io::simple_io& udg::io::simple_io::operator <<(short num) {

	*this << udg::lltostr(num);

}


io::simple_io& udg::io::simple_io::operator <<(char num) {

	char c[2] = {};
	c[0] = num;
	*this << c;

}

io::simple_io& udg::io::simple_io::operator <<(unsigned long long int num) {

	*this << udg::ulltostr(num);

}

io::simple_io& udg::io::simple_io::operator <<(unsigned long int num) {

	*this << udg::ulltostr(num);

}

io::simple_io& udg::io::simple_io::operator <<(unsigned int num) {

	*this << udg::ulltostr(num);

}

io::simple_io& udg::io::simple_io::operator <<(unsigned short num) {

	*this << udg::ulltostr(num);

}

io::simple_io& udg::io::simple_io::operator <<(unsigned char num) {

	*this << (char) num;

}
