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
#include <stdio.h>
#include "boost/shared_ptr.hpp"

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

			simple_io& operator<<(bool b);
		};

		extern simple_io cout;
		extern simple_io cdebug;

		class file {
			boost::shared_ptr<int> fd;

		public:

			file(const std::string& name, const std::string& mode = "r");
			ssize_t write(const void* data, size_t len);
			ssize_t read(void* buf, size_t len);

			long int seek(long int offset, int whence);
		};

		class DBSession {
			boost::shared_ptr<int> db_ref;
		public:
			DBSession(const char* filename, bool create_if_not_exists = true);
			void put(const char* key, const char* value, bool encrypt = true);
			ssize_t get(const char* key, char* out, size_t len, bool decrypt = true);
			void del(const char* key);

			~DBSession();
		};
	}
}

#endif /* SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_IO_HPP_ */
