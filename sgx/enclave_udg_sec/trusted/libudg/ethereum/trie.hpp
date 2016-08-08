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
#include "../array.hpp"
#include <vector>
#include <stddef.h>
#include <stdint.h>

namespace udg {
	namespace eth {

		struct Node {
			h256 hash() const = 0;
			virtual ~Node() {};
		};

		struct FullNode : public Node {
			udg::Array<udg::shared_ptr<Node>, 17> children;

			h256 hash() const;
		};

		struct ShortNode : public Node {
			std::vector<uint8_t> key;

			udg::shared_ptr<Node> val;
			h256 hash() const;
		};

		class Trie {
			io::DBSession db;
			h256 root_hash;
		public:
			Trie(const char* db_file);
			Trie(const char* db_file, h256 root_hash);



		};



		class MemoryTrie {
			udg::shared_ptr<Node> root;

			void insert(udg::shared_ptr<Node> node, const uint8_t prefix[], size_t prefix_len,
					const uint8_t key[], size_t key_len, const uint8_t val[], size_t val_len);
		public:

			h256 hash() const;
			void update(const uint8_t key[], size_t key_len, const uint8_t val[], size_t val_len);

		};
	}
}



#endif /* SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_ETHEREUM_TRIE_HPP_ */
