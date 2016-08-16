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
#include "boost/shared_ptr.hpp"
#include "rlp.hpp"
#include <vector>
#include <stddef.h>
#include <stdint.h>
#include <map>

namespace udg {
	namespace eth {

		struct Node: public rlp::RLPConvertable {
			virtual ~Node() {};
		};

		using node_ptr = boost::shared_ptr<Node>;

		struct FullNode : public Node {
			bool dirty;
			udg::Array<node_ptr, 17> children;
			rlp::rlpvec to_rlp() const;
			FullNode(bool dirty) : dirty(dirty) {}
		};

		struct ShortNode : public Node {
			bool dirty;
			std::vector<uint8_t> key;

			node_ptr val;

			ShortNode(std::vector<uint8_t> key, node_ptr val, bool dirty)
				: key(key), val(val), dirty(dirty) {}
			rlp::rlpvec to_rlp() const;
		};

		struct HashNode : public Node {
			h256 hash;

			HashNode() {}
			HashNode(const h256& h) : hash(h) {}
			rlp::rlpvec to_rlp() const;
		};

		struct ValueNode : public Node {
			std::vector<uint8_t> data;

			ValueNode() {}
			template <typename II>
			ValueNode(II begin, II end) : data(begin, end) {}
			rlp::rlpvec to_rlp() const;
		};

		struct TrieReturn {
			bool dirty;
			node_ptr node;

			TrieReturn(bool dirty, node_ptr node) : dirty(dirty), node(node) {}
		};

		struct HashReturn {
			node_ptr n1;
			node_ptr n2;
			h256 h;

			HashReturn(node_ptr n1, node_ptr n2) : n1(n1), n2(n2) {}
			HashReturn(node_ptr n1, node_ptr n2, h256 h) : n1(n1), n2(n2), h(h) {}
		};

		class MemoryTrie : public rlp::RLPConvertable {

			std::map<h256, node_ptr> data; // Store in memory instead of file
			node_ptr root;

			TrieReturn insert(node_ptr node, const std::vector<uint8_t>& prefix,
					const std::vector<uint8_t>& key, node_ptr val);

			TrieReturn deleet(node_ptr node, const std::vector<uint8_t>& prefix,
					const std::vector<uint8_t>& key);

			node_ptr resolve_hash(
					h256 h,
					const std::vector<uint8_t>& prefix,
					const std::vector<uint8_t>& key
					);

			node_ptr resolve(boost::shared_ptr<Node> node,
					const std::vector<uint8_t>& prefix,
					const std::vector<uint8_t>& key);

			h256 _hash_state;

			HashReturn hash(node_ptr node);
			HashReturn hash_root();
			HashReturn hash_children(node_ptr original);
			node_ptr store(node_ptr);

			rlp::rlpvec rlpify(node_ptr node);

		public:

			h256 hash();
			void update(const std::vector<uint8_t>& key, const std::vector<uint8_t>& val);
			void update(const std::string& key, const std::string& val);

			rlp::rlpvec to_rlp();
			rlp::rlpvec to_rlp() const;

		};
	}
}

#endif /* SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_ETHEREUM_TRIE_HPP_ */
