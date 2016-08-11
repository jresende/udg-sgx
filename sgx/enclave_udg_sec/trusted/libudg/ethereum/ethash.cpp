/*
 * ethash.cpp
 *
 *  Created on: Aug 6, 2016
 *      Author: nsamson
 */

#include "ethash.hpp"
#include <math.h>
#include <stdexcept>
#include <algorithm>
#include <map>
#include "../io.hpp"

using namespace udg;
using namespace udg::eth;
using namespace udg::eth::ethash;
using namespace udg::crypto;

bool isprime(uint64_t n) {

	if (n == 0) {
		return false;
	} else if (n <= 3) {
		return true;
	} else if (!(n & 0x1)) {
		return false;
	}

	uint64_t lim = (uint64_t) ceil(sqrt((double)n));

	for (uint64_t i = 3; i <= lim; i+=2) {
		if (n % i == 0) {
			return false;
		}
	}

	return true;

}

uint64_t udg::eth::ethash::get_cache_size(uint64_t block_number) {
	uint64_t sz = CACHE_BYTES_INIT + CACHE_BYTES_GROWTH * (block_number / EPOCH_LENGTH);
	sz -= HASH_BYTES;

	while (!isprime(sz / HASH_BYTES)) {
		sz -= 2 * HASH_BYTES;
	}

	return sz;
}

uint64_t udg::eth::ethash::get_full_size(uint64_t block_number) {
	uint64_t sz = DATASET_BYTES_INIT + DATASET_BYTES_GROWTH * (block_number / EPOCH_LENGTH);
	sz -= MIX_BYTES;

	while (!isprime(sz / MIX_BYTES)) {
		sz -= 2 * MIX_BYTES;
	}

	return sz;
}

h256 udg::eth::ethash::get_seedhash(uint64_t block_number) {
	h256 ret;

	uint64_t const epochs = block_number / EPOCH_LENGTH;

	for (uint64_t i = 0; i < epochs; i++) {
		crypto::keccak256 ctxt;
		ctxt.update(ret.data(), h256::size);
		ctxt.finalize();
		ctxt.get_digest(ret.data());
	}

	return ret;
}

udg::eth::EthashCache::EthashCache(uint64_t cache_size, h256 seed) {
	if (cache_size % h512::size != 0) {
		throw std::invalid_argument("cache size must be multiple of h512::size");
	}

	uint32_t num_nodes = (uint32_t) cache_size / h512::size;

	boost::shared_ptr<h512> first(new h512);
	this->values.push_back(first);

	keccak512 ctxt;
	ctxt.update(seed);
	ctxt.finalize();
	*first = ctxt.get_digest();

	for (uint32_t i = 1; i < num_nodes; i++) {
		boost::shared_ptr<h512> next(new h512);
		ctxt = keccak512();
		ctxt.update(*values[i-1]);
		ctxt.finalize();
		*next = ctxt.get_digest();
		values.push_back(next);
	}

	for (uint32_t j = 0; j < CACHE_ROUNDS; j++) {
		for (uint32_t i = 0; i < num_nodes; i++) {
			auto wrd = this->values[i]->slice<WORD_BYTES>(0);
			uint32_t word = *reinterpret_cast<uint32_t*>(wrd.data());
			uint32_t index = word % num_nodes;

			h512 data;
			data = *values[(num_nodes - 1 + i) % num_nodes];

			for (uint32_t w = 0; w < NODE_WORDS; w++) {
				auto data_word = data.slice<WORD_BYTES>(w * WORD_BYTES);
				data_word ^= values[index]->slice<WORD_BYTES>(w * WORD_BYTES);
				std::copy(data_word.begin(), data_word.end(), data.begin() + (w * WORD_BYTES));
			}

			ctxt = keccak512();
			ctxt.update(data);
			ctxt.finalize();
			*values[i] = ctxt.get_digest();
		}
	}

}

boost::shared_ptr<h512> udg::eth::EthashCache::operator [](uint64_t index) {
	return this->values[index];
}

h512 udg::eth::EthashCache::calc_dataset_item(uint64_t i) {
	auto n = values.size();
	auto r = HASH_BYTES / WORD_BYTES;

	h512 mix(*values[i % n]);
	mix.slice_ref<WORD_BYTES>(0) ^= FixedSizedByteArray<WORD_BYTES>::from<uint32_t>((uint32_t)i);
	uint32_t node_index = (uint32_t) i;

	keccak512 ctxt;
	ctxt.update(mix);
	ctxt.finalize();
	mix = ctxt.get_digest();

	for (uint32_t j = 0; j < DATASET_PARENTS; j++) {
		auto cache_index = ethash::fnv(node_index ^ j,
				mix.reinterpret_at<uint32_t>((j % r) * WORD_BYTES));

		uint32_t fnv_results[h512::size / WORD_BYTES] = {};

		auto companion = *values[cache_index % n];

		for (uint32_t i = 0; i < NODE_WORDS; i++) {
			uint32_t relevant_mix_word = mix
					.reinterpret_at<uint32_t>(i * WORD_BYTES);

			uint32_t relevant_companion_word = companion
					.reinterpret_at<uint32_t>(i * WORD_BYTES);

			fnv_results[i] = fnv(relevant_mix_word, relevant_companion_word);
		}

		uint8_t* fnv_r = reinterpret_cast<uint8_t*>(fnv_results);
		mix = h512(fnv_r, fnv_r + h512::size);

	}

	ctxt = keccak512();
	ctxt.update(mix);
	ctxt.finalize();
	return ctxt.get_digest();
}

EthashResult udg::eth::EthashCache::hashimoto(uint64_t full_size, h256 header_hash, FixedSizedByteArray<8> nonce,
		bool be_nonce) {

	if (full_size % MIX_WORDS != 0) {
		throw std::invalid_argument("");
	}

	h512 s_mix;
	std::copy(header_hash.begin(), header_hash.end(), s_mix.begin());

	if (be_nonce) {
		nonce = nonce.reverse();
	}

	std::copy(nonce.begin(), nonce.end(), s_mix.begin() + (4 * WORD_BYTES * 2));

	keccak512 ctxt;
	ctxt.update(s_mix.data(), 40);
	ctxt.finalize();
	s_mix = ctxt.get_digest();

	h1024 mix;

	std::copy(s_mix.begin(), s_mix.end(), mix.begin());
	std::copy(s_mix.begin(), s_mix.end(), mix.begin() + h512::size);

	io::cdebug << "Post copy mix"
				<< mix.to_string();

	uint32_t page_size = sizeof(uint32_t) * MIX_WORDS;
	uint32_t num_full_pages = (uint32_t) (full_size / page_size);

	io::cdebug << num_full_pages;

	for (uint32_t i = 0; i < ACCESSES; i++) {
		uint32_t index = ethash::fnv(
				s_mix.reinterpret_at<uint32_t>(0) ^ i,
				mix.reinterpret_at<uint32_t>((i % MIX_WORDS) * WORD_BYTES)
		) % num_full_pages;

		for (uint32_t n = 0; n < MIX_NODES; n++) {
			h512 dag_node = this->calc_dataset_item(index * MIX_NODES + n);

			for (uint32_t w = 0; w < NODE_WORDS; w++) {
				auto fnv_hash = FixedSizedByteArray<4>::from<uint32_t>(
						fnv(
								mix.reinterpret_at<uint32_t>(w * WORD_BYTES + n * (h1024::size / 2)),
								dag_node.reinterpret_at<uint32_t>(w * WORD_BYTES)
						)
				);

				std::copy(fnv_hash.begin(), fnv_hash.end(), mix.begin() + (w * WORD_BYTES) + (n * 64));
			}
		}

		io::cdebug << "Mix digest after access " << i
							<< mix.to_string();

	}

	for (uint32_t w = 0; w < MIX_WORDS; w += 4) {
		uint32_t reduction = mix.reinterpret_at<uint32_t>((w + 0) * WORD_BYTES);
		reduction = reduction * FNV_PRIME ^ mix.reinterpret_at<uint32_t>((w + 1) * WORD_BYTES);
		reduction = reduction * FNV_PRIME ^ mix.reinterpret_at<uint32_t>((w + 2) * WORD_BYTES);
		reduction = reduction * FNV_PRIME ^ mix.reinterpret_at<uint32_t>((w + 3) * WORD_BYTES);
		auto red_bytes = FixedSizedByteArray<4>::from<uint32_t>(reduction);
		std::copy(red_bytes.begin(), red_bytes.end(), mix.begin() + ((w / 4) * WORD_BYTES));
	}

	EthashResult ret;
	ret.mix_digest = h256(mix.begin(), mix.begin() + 32);

	auto ctxt256 = keccak256();
	ctxt256.update(s_mix);
	ctxt256.update(mix.data(), 32);
	ctxt256.finalize();
	ret.result = ctxt256.get_digest();

	return ret;
}

std::pair<uint64_t, EthashCache> ethash_cache_cache(0xFFFFFFFFFFFFFFFFULL, EthashCache());

EthashCache udg::eth::ethash::get_cache(uint64_t block_number) {
	if (ethash_cache_cache.first == (block_number / EPOCH_LENGTH)) {
		return ethash_cache_cache.second;
	} else {
		EthashCache ret(ethash::get_cache_size(block_number), ethash::get_seedhash(block_number));
		ethash_cache_cache.first = block_number / EPOCH_LENGTH;
		ethash_cache_cache.second = ret;
		return ret;
	}
}
