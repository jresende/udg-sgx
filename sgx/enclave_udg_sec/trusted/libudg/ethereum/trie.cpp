/*
 * trie.cpp
 *
 *  Created on: Aug 7, 2016
 *      Author: nsamson
 */

#include "trie.hpp"
#include "../crypto/all_hash.hpp"
#include "../io.hpp"
#include <algorithm>
#include <stdexcept>

using namespace udg;
using namespace udg::eth;
using namespace udg::rlp;

const h256 empty_root = h256("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");
const h256 empty_state = h256("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

#define TRIE_DEBUG 1

void trie_debug_func(const char* c) {
#if TRIE_DEBUG
	io::cdebug << c;
#endif
}

io::simple_io trie_debug(trie_debug_func);

std::vector<uint8_t> udg::eth::compact_encode(std::vector<uint8_t> ref) {
	uint8_t terminator = 0;
	std::vector<uint8_t> out;
	if (ref.back() == 16) {
		terminator = 1;
		ref.pop_back();
	}
	uint8_t odd = (uint8_t) (ref.size() % 2);
	size_t buf_len = ref.size()/2 + 1;
	size_t bi, hi;
	bi = hi = 0;
	uint8_t hs = 0;
	if (odd == 0) {
		bi = 1;
		hs = 4;
	}

	out.resize(buf_len, 0);
	out[0] = (terminator << 5) | (odd << 4);

	while (bi < out.size() && hi < ref.size()) {
		out[bi] |= ref[hi] << hs;
		if (hs == 0) {
			bi++;
		}

		hi++;
		hs ^= (1<<2);
	}

	return out;
}

std::vector<uint8_t> udg::eth::compact_hex_decode(const std::vector<uint8_t>& str) {
	std::vector<uint8_t> nibbles;

	for (auto b : str) {
		nibbles.push_back(b / 16);
		nibbles.push_back(b % 16);
	}

	nibbles.push_back(16);

	return nibbles;
}

std::vector<uint8_t> udg::eth::compact_hex_encode(const std::vector<uint8_t>& nibbles) {
	auto nl = nibbles.size();
	if (nl == 0) {
		return std::vector<uint8_t>();
	}

	if (nibbles[nl - 1] == 16) {
		nl--;
	}

	auto l = (nl + 1) / 2;
	std::vector<uint8_t> str;
	str.resize(l, 0);

	for (size_t i = 0; i < l; i++) {
		auto b = nibbles[i*2] * 16;
		if (nl > i * 2) {
			b += nibbles[i*2+1];
		}
		str[i] = b;
	}

	return str;
}

std::vector<uint8_t> udg::eth::compact_decode(const std::vector<uint8_t>& str) {
	auto base = compact_hex_decode(str);
	base.pop_back();
	if (base[0] >= 2) {
		base.push_back(16);
	}

	if (base[0] % 2 == 1) {
		base.erase(base.begin());
	} else {
		base.erase(base.begin(), base.begin() + 2);
	}
	return base;
}

//... what is the difference between this and compact_decode?
std::vector<uint8_t> udg::eth::decode_compact(const std::vector<uint8_t>& key) {
	auto l = key.size() / 2;
	std::vector<uint8_t> res;
	res.resize(l, 0);

	for (size_t i = 0; i < l; i++) {
		uint8_t v0, v1;
		v0 = key[2*i+1];
		v1 = key[2*i];
		res[i] = v1*16 + v0;
	}
	return res;
}

template <typename _II, typename _II2>
static size_t prefix_len(_II a, _II a_end, _II2 b, _II2 b_end) {
	auto len_a = std::distance(a, a_end);
	auto len_b = std::distance(b, b_end);
	auto search_len = len_a > len_b ? len_b : len_a;

	long i = 0;
	for (; i < search_len; i++, ++a, ++b) {
		if (*a != *b) {
			break;
		}
	}

	return i;
}

bool udg::eth::has_terminator(const std::vector<uint8_t>& ref) {
	return ref.back() == 16;
}

std::vector<uint8_t> udg::eth::remove_terminator(const std::vector<uint8_t>& ref) {
	if (has_terminator(ref)) {
		return std::vector<uint8_t>(ref.begin(), ref.end() - 1);
	} else {
		return std::vector<uint8_t>(ref);
	}
}

static std::vector<uint8_t> concat(const std::vector<uint8_t>& v1, const std::vector<uint8_t>& v2) {
	std::vector<uint8_t> out(v1.begin(), v1.end());
	out.insert(out.end(), v2.begin(), v2.end());
	return out;
}

template <typename II, typename II2>
static std::vector<uint8_t> concat(II v1, II v1_end, II2 v2, II2 v2_end) {
	std::vector<uint8_t> out(v1, v1_end);
	out.insert(out.end(), v2, v2_end);
	return out;
}

static std::string node_str(node_ptr node) {
	auto short_node = boost::dynamic_pointer_cast<ShortNode>(node);
	std::string out;
	if (short_node) {
		out.append("Short {");
		out.append(udg::hex_encode(short_node->key)).append(" : ");
		out.append(node_str(short_node->val)).append("}");
		return out;
	}

	auto full_node = boost::dynamic_pointer_cast<FullNode>(node);
	if (full_node) {
		out.append("Full {\n");
		for (uint8_t i = 0; i < full_node->children.size; i++) {
			out.append(node_str(full_node->children[i])).append(", ");
		}
		out.append("}");
		return out;
	}

	if (!node) {
		out.append("nil");
		return out;
	}

	auto hash_node = boost::dynamic_pointer_cast<HashNode>(node);
	if (hash_node) {
		out.append("Hash {").append(hash_node->hash.to_string()).append("}");
		return out;
	}

	auto val_node = boost::dynamic_pointer_cast<ValueNode>(node);
	if (val_node) {
		out.append("Value {").append(udg::hex_encode(val_node->data)).append("}");
		return out;
	}

	return out;
}

TrieReturn udg::eth::MemoryTrie::insert(
		node_ptr node,
        const std::vector<uint8_t>& prefix,
        const std::vector<uint8_t>& key,
        node_ptr value) {

	trie_debug << "Entering insert function with node:"
			<< node_str(node)
			<< "and value:"
			<< node_str(value)
			<< "with prefix/key:"
			<< udg::hex_encode(prefix)
			<< udg::hex_encode(key)
			<< "\n";

	if (key.size() == 0) {
		auto val_node = boost::dynamic_pointer_cast<ValueNode>(node);
		if (val_node) {
			bool dirty = val_node->data ==
					boost::dynamic_pointer_cast<ValueNode>(value)->data;
			return TrieReturn(dirty, value);
		}

		return TrieReturn(true, value);
	}

	auto short_node = boost::dynamic_pointer_cast<ShortNode>(node);
	if (short_node) {
		auto match_len = prefix_len(key.begin(), key.end(),
				short_node->key.begin(), short_node->key.end());

		if (match_len == short_node->key.size()) {
			auto nn = this->insert(
					short_node->val,
					concat(prefix.begin(), prefix.end(), key.begin(), key.begin() + match_len),
					std::vector<uint8_t>(key.begin() + match_len, key.end()),
					value);

			if (!nn.dirty) {
				return TrieReturn(false, short_node);
			}

			return TrieReturn(true, node_ptr(new ShortNode(short_node->key, nn.node, true)));
		}

		boost::shared_ptr<FullNode> branch(new FullNode(true));
		branch->children[short_node->key[match_len]] =
				this->insert(
						node_ptr(),
						concat(prefix.begin(), prefix.end(), short_node->key.begin(), short_node->key.begin() + match_len + 1),
						std::vector<uint8_t>(short_node->key.begin() + match_len + 1, short_node->key.end()),
						short_node->val).node;

		branch->children[key[match_len]] =
				this->insert(
						node_ptr(),
						concat(prefix.begin(), prefix.end(), key.begin(), key.begin() + match_len + 1),
						std::vector<uint8_t>(key.begin() + match_len + 1, key.end()),
						value
				).node;

		if (match_len == 0) {
			return TrieReturn(true, branch);
		}

		return TrieReturn(
				true,
				node_ptr(new ShortNode(std::vector<uint8_t>(key.begin(), key.begin() + match_len), branch, true))
		);
	}

	auto full_node = boost::dynamic_pointer_cast<FullNode>(node);
	if (full_node) {
		auto nn =
				this->insert(
						full_node->children[key[0]],
						concat(prefix.begin(), prefix.end(), key.begin(), key.begin() + 1),
						std::vector<uint8_t>(key.begin() + 1, key.end()),
						value
					);

		if (!nn.dirty) {
			return TrieReturn(false, full_node);
		}

		full_node->children[key[0]] = nn.node;
		full_node->dirty = true;

		return TrieReturn(true, full_node);
	}

	if (!node) {
        //trie_debug << "Creating new short_node:"
        //    << udg::hex_encode(key)
        //    << node_str(value);
		return TrieReturn(true,
				node_ptr(new ShortNode(key, value, true)));
	}

	auto hash_node = boost::dynamic_pointer_cast<HashNode>(node);
	if (hash_node) {
		auto rn = this->resolve_hash(hash_node->hash, prefix, key);
		auto nn = this->deleet(rn, prefix, key);

		if (!nn.dirty) {
			return TrieReturn(false, rn);
		}

		return TrieReturn(true, rn);
	}

	throw std::runtime_error("Invalid node insertion."); // PANIC
}

h256 udg::eth::MemoryTrie::hash() {
	trie_debug << "PRE HASH"
				<< node_str(this->root);
	auto r = this->hash_root(true);

	trie_debug << "POST HASH ROOT"
			<< node_str(this->root);

	this->root = r.n2;
	trie_debug << "POST HASH"
				<< node_str(this->root);
	return boost::dynamic_pointer_cast<HashNode>(r.n1)->hash;

}

TrieReturn udg::eth::MemoryTrie::deleet(node_ptr node,
    const std::vector<uint8_t>& prefix, const std::vector<uint8_t>& key) {

	auto short_node = boost::dynamic_pointer_cast<ShortNode>(node);
	if (short_node) {
		auto match_len = prefix_len(key.begin(), key.end(),
						short_node->key.begin(), short_node->key.end());

		if (match_len < short_node->key.size()) {
			return TrieReturn(false, short_node);
		}

		if (match_len == key.size()) {
			return TrieReturn(true, node_ptr());
		}

		auto child =
				this->deleet(
						short_node->val,
						concat(prefix.begin(), prefix.end(), key.begin(), key.begin() + short_node->key.size()),
						std::vector<uint8_t>(key.begin() + short_node->key.size(), key.end())
				);

		if (!child.dirty) {
			return TrieReturn(false, node);
		}

		auto short_child = boost::dynamic_pointer_cast<ShortNode>(child.node);
		if (short_child) {
			return TrieReturn(true,
					node_ptr(new ShortNode(concat(short_node->key, short_child->key), short_child->val, true))
			);
		} else {
			return TrieReturn(true,
					node_ptr(new ShortNode(short_node->key, short_child, true))
			);
		}

	} // shortnode

	auto full_node = boost::dynamic_pointer_cast<FullNode>(node);
	if (full_node) {
		auto nn =
				this->deleet(
						full_node->children[key[0]],
						concat(prefix.begin(), prefix.end(), key.begin(), key.begin() + 1),
						std::vector<uint8_t>(key.begin() + 1, key.end())
				);

		if (!nn.dirty) {
			return TrieReturn(false, full_node);
		}

		full_node->children[key[0]] = nn.node;
		full_node->dirty = true;

		long pos = -1;
		for (long i = 0; i < (long) full_node->children.size; i++) {
			auto cld = full_node->children[i];
			if (cld) {
				if (pos == -1) {
					pos = i;
				} else {
					pos = -2;
					break;
				}
			}
		}

		if (pos >= 0) {
			std::vector<uint8_t> pos_v;
			pos_v.push_back((uint8_t)pos);
			if (pos != 16) {
				auto cnode = this->resolve(full_node->children[pos], prefix, pos_v);
				auto c_short = boost::dynamic_pointer_cast<ShortNode>(cnode);
				if (c_short) {
					auto k = concat(pos_v, c_short->key);
					return TrieReturn(true,
							boost::shared_ptr<ShortNode>(new ShortNode(k, c_short->val, true)));
				}
			}

			return TrieReturn(true,
					boost::shared_ptr<ShortNode>(new ShortNode(pos_v, full_node->children[pos], true)));
		}

		return TrieReturn(true, full_node);
	} // full node

	if (!node) {
		return TrieReturn(false, node_ptr());
	}

	auto hash_node = boost::dynamic_pointer_cast<HashNode>(node);
	if (hash_node) {
		auto rn = this->resolve_hash(hash_node->hash, prefix, key);
		auto nn = this->deleet(rn, prefix, key);

		if (!nn.dirty) {
			return TrieReturn(false, rn);
		}

		return TrieReturn(true, nn.node);
	}

	throw std::runtime_error("Invalid node deletion."); // PANIC
}

void udg::eth::MemoryTrie::update(const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& val) {
	auto k = compact_hex_decode(key);

	if (val.size() != 0) {
		auto n = this->insert(this->root, std::vector<uint8_t>(), k,
				node_ptr(new ValueNode(val.begin(), val.end())));
		this->root = n.node;
	} else {
		auto n = this->deleet(this->root, std::vector<uint8_t>(), k);
		this->root = n.node;
	}
}

node_ptr udg::eth::MemoryTrie::resolve_hash(h256 h,
        const std::vector<uint8_t>& prefix, const std::vector<uint8_t>& key) {
	auto n = decode_node(this->data[h]);
	trie_debug << "Decoded node"
			<< node_str(n);
	return n;
}

node_ptr udg::eth::MemoryTrie::resolve(
        node_ptr node, const std::vector<uint8_t>& prefix,
        const std::vector<uint8_t>& key) {
	auto hash_node = boost::dynamic_pointer_cast<HashNode>(node);
	if (hash_node) {
		return this->resolve_hash(hash_node->hash, prefix, key);
	}

	return node;
}

HashReturn udg::eth::MemoryTrie::hash(node_ptr node, bool force, bool db) {
    trie_debug << "Entering hash function with node:"
		<< node_str(node);

    auto cd = node->cache();
    if ((db == false || !cd.dirty) && cd.has_hash()) {
    	trie_debug << "USED CACHED RESULT";
    	return HashReturn(node_ptr(new HashNode(cd.hash)), node, cd.hash);
    }

	auto rcc = this->hash_children(node, db);
	auto collapsed = rcc.n1;
	auto cached = rcc.n2;

	auto hashed = this->store(collapsed, force, db);

	auto hash_ptr = boost::dynamic_pointer_cast<HashNode>(hashed);
	if (hash_ptr && !force) {
		auto cached_short = boost::dynamic_pointer_cast<ShortNode>(cached);
		if (cached_short) {
			cached_short->hash_cache = hash_ptr->hash;
			if (!db) {
				cached_short->dirty = false;
			}
            trie_debug << "Short return.";
			return HashReturn(hashed, cached, hash_ptr->hash);
		}


        auto cached_full = boost::dynamic_pointer_cast<FullNode>(cached);
		if (cached_full) {
			cached_full->hash_cache = cd.hash;
			if (!db) {
				cached_full->dirty = false;
			}
		}
      trie_debug << "Full return.";
		return HashReturn(hashed, cached, hash_ptr->hash);
	}

	return HashReturn(hashed, cached);
}

HashReturn udg::eth::MemoryTrie::hash_root(bool db) {
	if (!this->root) {
		return HashReturn(node_ptr(new HashNode(empty_root)), node_ptr(), empty_root);
	}

	return this->hash(this->root, true, db);
}

HashReturn udg::eth::MemoryTrie::hash_children(node_ptr original, bool db) {
	trie_debug << "Entering hash_children function with node:"
		<< node_str(original);

	auto short_node = boost::dynamic_pointer_cast<ShortNode>(original);
	if (short_node) {
		auto cached = boost::shared_ptr<ShortNode>(
				new ShortNode(short_node->key, short_node->val, short_node->dirty));

		trie_debug << "Cached node before alter"
				<< node_str(cached);
		short_node->key = compact_encode(short_node->key);
		if (!boost::dynamic_pointer_cast<ValueNode>(short_node->val)) {
			auto hr = this->hash(short_node->val, false, db);
			short_node->val = hr.n1;
			cached->val = hr.n2;
		}

		if (!short_node->val) {
			short_node->val = node_ptr(new ValueNode());
		}

		trie_debug << "Cached node after alter"
						<< node_str(cached);

		return HashReturn(short_node, cached);
	}

	auto full_node = boost::dynamic_pointer_cast<FullNode>(original);
	if (full_node) {
		auto cached = boost::shared_ptr<FullNode>(new FullNode(full_node->dirty));

		for (uint8_t i = 0; i < 16; i++) {
			if (full_node->children[i]) {
				auto hc = this->hash(full_node->children[i], false, db);
				full_node->children[i] = hc.n1;
				cached->children[i] = hc.n2;
			} else {
				full_node->children[i] = node_ptr(new ValueNode());
			}
		}

		cached->children[16] = full_node->children[16];
		if (!full_node->children[16]) {
			full_node->children[16] = node_ptr(new ValueNode());
		}

		return HashReturn(full_node, cached);

	}

	return HashReturn(original, original);
}

node_ptr udg::eth::MemoryTrie::store(node_ptr node, bool force, bool db) {
    trie_debug << "Entered store with node:"
        << node_str(node);
	if (!node || boost::dynamic_pointer_cast<HashNode>(node)) {
		return node;
	}

	auto tmp = node->to_rlp();

    if (tmp.size() < 32 && !force) {
        trie_debug << "Returning node as is.";
        return node;
    }

    boost::shared_ptr<HashNode> hash;
    CacheData cd = node->cache();

    if (!cd.has_hash()) {
    	crypto::keccak256 ctxt;
		ctxt.update(&tmp[0], tmp.size());
		ctxt.finalize();
		hash = boost::shared_ptr<HashNode>(new HashNode(ctxt.get_digest()));
    } else {
    	hash = boost::shared_ptr<HashNode>(new HashNode(cd.hash));
    }



	if (db) {
		trie_debug << "Storing!";
		this->data[hash->hash] = node->to_rlp();
	}
    trie_debug << "Node has hash:"
        << hash->hash.to_string();

	return hash;
}

rlp::rlpvec udg::eth::MemoryTrie::rlpify(node_ptr node) {
	if (!node) {
		return rlp::to_rlp("", 0);
	}

	auto hash_node = boost::dynamic_pointer_cast<HashNode>(node);
	if (hash_node) {
		return this->rlpify(decode_node(this->data[hash_node->hash]));
	}

	auto short_node = boost::dynamic_pointer_cast<ShortNode>(node);
	if (short_node) {
		rlp::rlpvec key = rlp::to_rlp(short_node->key);
		rlp::rlpvec val = this->rlpify(short_node->val);
		std::vector<rlp::rlpvec> d;
		d.push_back(key);
		d.push_back(val);
		return rlp::to_rlp_list(d);
	}

	auto full_node = boost::dynamic_pointer_cast<FullNode>(node);
	if (full_node) {
		std::vector<rlp::rlpvec> d;
		for (auto c : full_node->children) {
			d.push_back(this->rlpify(c));
		}
		return rlp::to_rlp_list(d);
	}

	auto val_node = boost::dynamic_pointer_cast<ValueNode>(node);
	if (val_node) {
		return val_node->to_rlp();
	}

	throw std::runtime_error("Should never get here");
}

std::vector<rlp::rlpvec> udg::eth::MemoryTrie::prove(
        const std::vector<uint8_t>& key) {

	auto k = compact_hex_decode(key);

	std::vector<node_ptr> nodes;
	auto tn = this->root;

	while (k.size() > 0 && tn) {
		auto short_node = boost::dynamic_pointer_cast<ShortNode>(tn);
		auto full_node = boost::dynamic_pointer_cast<FullNode>(tn);
		auto hash_node = boost::dynamic_pointer_cast<HashNode>(tn);
		if (short_node) {
			if (k.size() < short_node->key.size()
					|| short_node->key != std::vector<uint8_t>(k.begin(), k.begin() + short_node->key.size())) {
				tn = node_ptr();
			} else {
				tn = short_node->val;
				k.erase(k.begin(), k.begin() + short_node->key.size());
			}
			nodes.push_back(short_node);
		} else if (full_node) {
			tn = full_node->children[k[0]];
			k.erase(k.begin(), k.begin() + 1);
			nodes.push_back(full_node);
		} else if (hash_node) {
			tn = this->resolve_hash(hash_node->hash, std::vector<uint8_t>(), std::vector<uint8_t>());
		} else {
			throw std::runtime_error("Unhandled trie error! ");
		}
	}

	std::vector<rlp::rlpvec> proof;
	for (size_t i = 0; i < nodes.size(); i++) {
		auto n = nodes[i];

		auto hashn = this->hash_children(n, false);
		trie_debug <<
				std::string("Hash children output for ")
					.append(udg::ulltostr(i))
					.append(": ")
					.append(node_str(hashn.n1));
		n = hashn.n1;

		auto hn = this->store(n, false, false);
		auto hash_node = boost::dynamic_pointer_cast<HashNode>(hn);
		if (hash_node || i == 0) {
			proof.push_back(n->to_rlp());
		}

	}

	return proof;

}

struct GetReturn {
	std::vector<uint8_t> key;
	node_ptr node;

	GetReturn(const std::vector<uint8_t> key, node_ptr node): key(key), node(node) {}
};

static GetReturn get(node_ptr tn, std::vector<uint8_t> key) {

	while (key.size() > 0) {
		auto short_node = boost::dynamic_pointer_cast<ShortNode>(tn);
		auto full_node = boost::dynamic_pointer_cast<FullNode>(tn);
		auto hash_node = boost::dynamic_pointer_cast<HashNode>(tn);

		if (short_node) {
			if (key.size() < short_node->key.size()
					|| short_node->key != std::vector<uint8_t>(key.begin(), key.begin() + short_node->key.size())) {
				return GetReturn(std::vector<uint8_t>(), node_ptr());
			}
			tn = short_node->val;
			key.erase(key.begin(), key.begin() + short_node->key.size());
		} else if (full_node) {
			tn = full_node->children[key[0]];
			key.erase(key.begin(), key.begin() + 1);
		} else if (hash_node) {
			return GetReturn(key, hash_node);
		} else if (!tn) {
			return GetReturn(key, node_ptr());
		} else {
			throw std::runtime_error("Invalid node!");
		}

	}

	return GetReturn(std::vector<uint8_t>(), tn);
}

bool udg::eth::MemoryTrie::verify_proof(h256 root_hash,
        const std::vector<uint8_t>& key,
        const std::vector<rlp::rlpvec>& proof) {

	auto k = compact_hex_decode(key);
	auto sha = crypto::keccak256();
	h256 want_hash = root_hash;

	for (size_t i = 0; i < proof.size(); i++) {
		auto& buf = proof[i];

		sha = crypto::keccak256();
		sha.update(&buf[0], buf.size());
		sha.finalize();

		if (sha.get_digest() != want_hash) {
			return false;
		}

		RLPData pbuf;
		pbuf.parse_bytes(buf.begin(), buf.end());
		auto n = decode_node(pbuf);
		auto gr = get(n, k);
		auto keyrest = gr.key;
		auto cld = gr.node;

		auto hash_node = boost::dynamic_pointer_cast<HashNode>(cld);
		auto val_node = boost::dynamic_pointer_cast<ValueNode>(cld);
		if (!cld) {
			if (i != proof.size() - 1) {
				return false;
			} else {
				return false;
			}
		} else if (hash_node) {
			k = keyrest;
			want_hash = hash_node->hash;
		} else if (val_node) {
			if (i != proof.size() - 1) {
				return false;
			}
			return true;
		}

	}

	return false;

}

rlp::rlpvec udg::eth::MemoryTrie::to_rlp() const {
	return const_cast<MemoryTrie*>(this)->to_rlp(); // Sorry...
}

rlp::rlpvec udg::eth::MemoryTrie::to_rlp() {
	if (!this->root) {
		return rlp::to_rlp("", 0);
	} else {
		return this->rlpify(this->root);
	}
}

rlp::rlpvec udg::eth::FullNode::to_rlp() const {
	std::vector<rlp::rlpvec> data;

	for (auto& c : this->children) {
		data.push_back(c->to_rlp());
	}

	return rlp::to_rlp_list(data);
}

rlp::rlpvec udg::eth::ShortNode::to_rlp() const {
	std::vector<rlp::rlpvec> data;

	data.push_back(rlp::to_rlp(this->key));
	data.push_back(this->val->to_rlp());

	return rlp::to_rlp_list(data);
}

rlp::rlpvec udg::eth::HashNode::to_rlp() const {
    return this->hash.to_rlp_with_zeroes();
}

rlp::rlpvec udg::eth::ValueNode::to_rlp() const {
	return rlp::to_rlp(this->data);
}

void udg::eth::MemoryTrie::update(const std::string& key,
        const std::string& val) {
	trie_debug << "Entering update with key"
			<< udg::hex_encode(key);
	this->update(std::vector<uint8_t>(key.begin(), key.end()), std::vector<uint8_t>(val.begin(), val.end()));
}

node_ptr udg::eth::decode_node(const rlp::RLPData& dat) {
	rlpdlist elems;
	dat.retrieve_arr(elems);

	if (elems.size() == 2) {
		return decode_short(elems);
	} else if (elems.size() == 17) {
		return decode_full(elems);
	} else {
		throw std::invalid_argument("Invalid number of list elements.");
	}
}

node_ptr udg::eth::decode_short(const rlp::rlpdlist& dat) {
	rlpvec kbuf;
	dat[0].retrieve_bytes(kbuf);
	rlpdlist rest(dat.begin() + 1, dat.end());

	auto key = compact_decode(kbuf);
	trie_debug << std::string("decodeShort kbuf is ")
			.append(udg::hex_encode(kbuf))
			.append(" key is ")
			.append(udg::hex_encode(key));
	if (key.back() == 16) {
		// value node
		rlpvec val;
		rest[0].retrieve_bytes(val);
		return node_ptr(new ShortNode(key, node_ptr(new ValueNode(val.begin(), val.end())), false));
	}

	auto r = decode_ref(rest);

	return node_ptr(new ShortNode(key, r.node, false));
}

node_ptr udg::eth::decode_full(rlp::rlpdlist elems) {

	auto n = boost::shared_ptr<FullNode>(new FullNode(false));
	for (uint8_t i = 0; i < 16; i++) {
		auto refr = decode_ref(elems);
		auto cld = refr.node;
		auto rest = refr.rd;

		n->children[i] = cld;
		elems = rest;
	}

	rlpvec val;
	elems.front().retrieve_bytes(val);
	if (val.size() > 0) {
		n->children[16] = node_ptr(new ValueNode(val.begin(), val.end()));
	}

	return n;

}

node_ptr udg::eth::decode_node(const rlp::rlpvec& r) {
	RLPData dat;
	dat.parse_bytes(r.begin(), r.end());
	return decode_node(dat);
}

RefReturn udg::eth::decode_ref(const rlp::rlpdlist& elems) {
	auto& elem = elems[0];
	rlpdlist rest(elems.begin() + 1, elems.end());

	if (elem.is_arr()) {
		auto n = udg::eth::decode_node(elem);
		return RefReturn(n, rest);
	} else {
		rlpvec str;
		elem.retrieve_bytes(str);
		if (str.size() == 0) {
			return RefReturn(node_ptr(), rest);
		} else if (str.size() == 32) {
			return RefReturn(node_ptr(new HashNode(h256(str.begin(), str.end()))), rest);
		} else {
			throw std::runtime_error("Invalid RLP string size.");
		}
	}
}

std::string udg::eth::MemoryTrie::print_datastore() const {
	std::string out = "{";

	for (auto& kv : this->data) {
		out.append("    ");
		out.append(kv.first.to_string()).append(", ");
		out.append(node_str(decode_node(kv.second)));
		out.append("\n");
	}

	out.append("}");
	return out;
}
