/*
 * io.hpp
 *
 *  Created on: Jul 16, 2016
 *      Author: nsamson
 */

#ifndef SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_IO_HPP_
#define SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_IO_HPP_

#include <stdint.h>
#include <string>

namespace udg {

	namespace io {
		typedef void(*io_handler)(const char*);

		class simple_io {
			io_handler handler;

		public:
			simple_io(io_handler handler);

			void puts(const char* str);

			simple_io& operator<<(const std::string& str);
			simple_io& operator<<(const char* str);
			simple_io& operator<<(const uint8_t* str);

			simple_io& operator<<(long long int num);
			simple_io& operator<<(long int num);
			simple_io& operator<<(int num);
			simple_io& operator<<(short num);
			simple_io& operator<<(char num);

			simple_io& operator<<(unsigned long long int num);
			simple_io& operator<<(unsigned long int num);
			simple_io& operator<<(unsigned int num);
			simple_io& operator<<(unsigned short num);
			simple_io& operator<<(unsigned char num);
		};

		extern simple_io cout;
		extern simple_io cdebug;
	}
}

#endif /* SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_IO_HPP_ */
