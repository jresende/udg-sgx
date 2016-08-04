/*
 * trie.hpp
 *
 *  Created on: Aug 2, 2016
 *      Author: nsamson
 */

#ifndef SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_ETHEREUM_TRIE_HPP_
#define SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_ETHEREUM_TRIE_HPP_

#include "../io.hpp"
#include "../byte_array.hpp"

namespace udg {
	namespace eth {
		class Trie {
			io::DBSession db;
			h256 root_hash;
		public:
			Trie(const char* db_file);
			Trie(const char* db_file, h256 root_hash);



		};
	}
}



#endif /* SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_ETHEREUM_TRIE_HPP_ */
