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

		std::vector<uint8_t> compact_encode(std::vector<uint8_t> ref);
		std::vector<uint8_t> compact_hex_decode(const std::vector<uint8_t>& str);
		std::vector<uint8_t> compact_hex_encode(const std::vector<uint8_t>& nibbles);
		std::vector<uint8_t> compact_decode(const std::vector<uint8_t>& str);
		std::vector<uint8_t> decode_compact(const std::vector<uint8_t>& key);
		bool has_terminator(const std::vector<uint8_t>& ref);
		std::vector<uint8_t> remove_terminator(const std::vector<uint8_t>& ref);

		struct CacheData {
			bool dirty;
			h256 hash;

			bool has_hash() const {
				return hash != h256(0);
			}

			CacheData(bool dirty, const h256& hash) {
				this->dirty = dirty;
				this->hash = h256(hash);
			}

			CacheData(): dirty(false) {}
		};

		struct Node: public rlp::RLPConvertable {
			virtual ~Node() {};
			virtual CacheData cache() const {
				return CacheData();
			}
		};

		using node_ptr = boost::shared_ptr<Node>;

		node_ptr decode_node(const rlp::rlpvec&);
		node_ptr decode_node(const rlp::RLPData&);
		node_ptr decode_short(const rlp::rlpdlist&);
		node_ptr decode_full(rlp::rlpdlist);

		struct RefReturn {
			node_ptr node;
			rlp::rlpdlist rd;

			RefReturn (node_ptr n, const rlp::rlpdlist& b): node(n), rd(b) {}
		};

		RefReturn decode_ref(const rlp::rlpdlist&);

		struct FullNode : public Node {
			bool dirty;
			udg::Array<node_ptr, 17> children;
			rlp::rlpvec to_rlp() const;

			h256 hash_cache;

			FullNode(bool dirty, h256 hash = 0) : dirty(dirty), hash_cache(hash) {}

			CacheData cache() const {
				return CacheData(dirty, hash_cache);
			}
		};

		struct ShortNode : public Node {
			bool dirty;
			std::vector<uint8_t> key;

			node_ptr val;

			h256 hash_cache;

			ShortNode(std::vector<uint8_t> key, node_ptr val, bool dirty, h256 hash = 0)
				: key(key), val(val), dirty(dirty), hash_cache(hash) {}
			rlp::rlpvec to_rlp() const;

			CacheData cache() const {
				return CacheData(dirty, hash_cache);
			}
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

			std::map<h256, rlp::rlpvec> data; // Store in memory instead of file
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

			HashReturn hash(node_ptr node, bool force, bool db);
			HashReturn hash_root(bool db);
			HashReturn hash_children(node_ptr original, bool db);
			node_ptr store(node_ptr, bool, bool);

			rlp::rlpvec rlpify(node_ptr node);

		public:

			h256 hash();
			void update(const std::vector<uint8_t>& key, const std::vector<uint8_t>& val);
			void update(const std::string& key, const std::string& val);

			std::vector<rlp::rlpvec> prove(const std::vector<uint8_t>& key);
			static bool verify_proof(h256 root_hash, const std::vector<uint8_t>& key, const std::vector<rlp::rlpvec>& proof);

			rlp::rlpvec to_rlp();
			rlp::rlpvec to_rlp() const;

			std::string print_datastore() const;

		};
	}
}

#endif /* SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_ETHEREUM_TRIE_HPP_ */
