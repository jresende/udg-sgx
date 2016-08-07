#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "udg_sec.h"
#include "udg_sec_t.h"  /* print_string */
#include "libudg/ethereum/blockchain.hpp"
#include "libudg/hex_encode.hpp"
#include "libudg/io.hpp"
#include <stdexcept>

using namespace udg;

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print(buf);
}

int ecall_udg_sec_main()
{
  printf("IN UDG_SEC\n");
  return 0;
}

int ecall_udg_parse(const char* rlp) {
	try {
		auto bin_dat = udg::hex_decode(rlp);
		eth::Block blk(&bin_dat[0], bin_dat.size());
		io::cout << blk.to_string()
				<< "\nBlock Hash:"
				<< blk.hash().to_string() << "\n";
	} catch (std::runtime_error& e) {
		io::cout << e.what() << "\n";
	}

	return 0;
}

int ecall_udg_verify(const char* rlp) {
	try {
		auto bin_dat = udg::hex_decode(rlp);
		eth::Block blk(&bin_dat[0], bin_dat.size());
		io::cout << blk.to_string()
				<< "\nBlock Hash:"
				<< blk.hash().to_string() << "\n";

		bool valid = blk.validate();

		io::cout << "Is Valid Block? " << valid << "\n";

		return valid ? 0 : 1;

	} catch (std::runtime_error& e) {
		io::cout << e.what() << "\n";
	}

	return -1;
}
