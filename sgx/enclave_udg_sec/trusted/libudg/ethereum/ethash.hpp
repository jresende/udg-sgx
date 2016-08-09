/*
 * ethhash.hpp
 *
 *  Created on: Aug 6, 2016
 *      Author: nsamson
 */

#ifndef SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_ETHEREUM_ETHASH_HPP_
#define SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_ETHEREUM_ETHASH_HPP_

#include <stdint.h>
#include "../crypto/keccak.hpp"
#include "../byte_array.hpp"
#include "boost/shared_ptr.hpp"

namespace udg {
	namespace eth {

		struct EthashResult {
			h256 mix_digest;
			h256 result;
		};

		class EthashCache {
			std::vector<boost::shared_ptr<h512>> values;

		public:
			EthashCache() = default;
			EthashCache(uint64_t cache_size, h256 seed);

			boost::shared_ptr<h512> operator[](uint64_t index);

			h512 calc_dataset_item(uint64_t i);

			EthashResult hashimoto(uint64_t full_size, h256 header_hash, FixedSizedByteArray<8> nonce,
					bool be_nonce = true);

		};

		namespace ethash {
			const uint64_t WORD_BYTES = 4;
			const uint64_t DATASET_BYTES_INIT = 0x40000000;
			const uint64_t DATASET_BYTES_GROWTH = 0x800000;
			const uint64_t CACHE_BYTES_INIT = 0x1000000;
			const uint64_t CACHE_BYTES_GROWTH = 0x20000;
			const uint64_t CACHE_MULTIPLIER = 1024;
			const uint64_t EPOCH_LENGTH = 30000;
			const uint64_t MIX_BYTES = 128;
			const uint64_t HASH_BYTES = 64;
			const uint64_t DATASET_PARENTS = 256;
			const uint64_t CACHE_ROUNDS = 3;
			const uint64_t ACCESSES = 64;
			const uint64_t NODE_WORDS (64/WORD_BYTES);
			const uint64_t MIX_WORDS = MIX_BYTES / WORD_BYTES;
			const uint64_t MIX_NODES = MIX_WORDS / NODE_WORDS;

			const uint32_t FNV_PRIME = 0x01000193;

			uint64_t get_cache_size(uint64_t block_number);
			uint64_t get_full_size(uint64_t block_number);
			h256 get_seedhash(uint64_t block_number);
			constexpr uint32_t fnv(uint32_t const x, uint32_t const y) {
				return x * FNV_PRIME ^ y;
			}

			EthashCache get_cache(uint64_t block_number);

		}

	}
}

#endif /* SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_ETHEREUM_ETHASH_HPP_ */
