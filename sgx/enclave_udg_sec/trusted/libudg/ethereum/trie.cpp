/*
 * trie.cpp
 *
 *  Created on: Aug 7, 2016
 *      Author: nsamson
 */

#include "trie.hpp"
#include <algorithm>

using namespace udg;
using namespace udg::eth;

static std::vector<uint8_t> bin_to_nibbles(const uint8_t dat[], size_t dat_len) {

	std::vector<uint8_t> out;
	out.resize(dat_len * 2);

	for (size_t i = 0; i < dat_len; i++) {
		out[i*2] = dat[i] / 16;
		out[i*2 + 1] = dat[i] % 16;
	}

	return out;
}

static std::vector<uint8_t> nibbles_to_bin(const uint8_t nibs[], size_t nibs_len) {
	std::vector<uint8_t> out;

	for (size_t i = 0; i < nibs_len; i+=2) {
		out.push_back(16 * nibs[i] + nibs[i+1]);
	}

	return out;
}

# define NIBBLE_TERMINATOR 16

static std::vector<uint8_t> with_terminator(const uint8_t nibs[], size_t nibs_len) {
	if (nibs[nibs_len-1] == NIBBLE_TERMINATOR) {
		return std::vector<uint8_t>(nibs, nibs + nibs_len);
	} else {
		std::vector<uint8_t> out(nibs, nibs + nibs_len);
		out.push_back(NIBBLE_TERMINATOR);
		return out;
	}
}

static std::vector<uint8_t> without_terminator(const uint8_t nibs[], size_t nibs_len) {
	if (nibs[nibs_len-1] == NIBBLE_TERMINATOR) {
		return std::vector<uint8_t>(nibs, nibs + nibs_len - 1);
	} else {
		return std::vector<uint8_t>(nibs, nibs + nibs_len);
	}
}

static std::vector<uint8_t> adapt_terminator(const uint8_t nibs[], size_t nibs_len, bool term) {
	if (term) {
		return with_terminator(nibs, nibs_len);
	} else {
		return without_terminator(nibs, nibs_len);
	}
}

static std::vector<uint8_t> pack_nibbles(const uint8_t nibs[], size_t nibs_len) {

	uint8_t flags;

	std::vector<uint8_t> nibv(nibs, nibs + nibs_len);

	if (nibv[nibs_len-1] == NIBBLE_TERMINATOR) {
		flags = 2;
		nibv.pop_back();
	} else {
		flags = 0;
	}

	uint8_t oddlen = (uint8_t) (nibv.size() % 2);

	flags |= oddlen;

	if (oddlen != 0) {
		nibv.insert(nibv.begin(), flags);
	} else {
		nibv.insert(nibv.begin(), 0);
		nibv.insert(nibv.begin(), flags);
	}

	std::vector<uint8_t> out;

	for (size_t i = 0; i < nibv.size(); i += 2) {
		out.push_back(16 * nibv[i] + nibv[i + 1]);
	}

	return out;

}

static std::vector<uint8_t> unpack_to_nibbles(const uint8_t nibs[], size_t nibs_len) {
	auto o = bin_to_nibbles(nibs, nibs_len);
	uint8_t flags = o[0];

	if (flags & 2) {
		o.push_back(NIBBLE_TERMINATOR);
	}

	if (flags & 1 == 1) {
		o.erase(o.begin());
	} else {
		o.erase(o.begin(), o.begin() + 1);
	}

	return o;
}


static bool starts_with(const uint8_t full[], size_t full_len, const uint8_t part[], size_t part_len) {
	if (full_len < part_len) {
		return false;
	}

	return std::equal(full, full + part_len, part);
}


//h256 udg::eth::FullNode::hash() const {
//
//}
//
//h256 udg::eth::ShortNode::hash() const {
//
//}
//
//h256 udg::eth::MemoryTrie::hash() const {
//
//}

void udg::eth::MemoryTrie::insert(udg::shared_ptr<Node> node,
        const uint8_t prefix[], size_t prefix_len, const uint8_t key[],
        size_t key_len, const uint8_t val[], size_t val_len) {
}

void udg::eth::MemoryTrie::update(const uint8_t key[], size_t key_len,
        const uint8_t val[], size_t val_len) {

}
