//
// Created by nsamson on 7/10/16.
//

#ifndef UDG_BLOCKCHAIN_HPP
#define UDG_BLOCKCHAIN_HPP

#include "../byte_array.hpp"
#include "../BigInt.hpp"
#include "../crypto/ecc.hpp"
#include "rlp.hpp"
#include <stdint.h>
#include <vector>
#include <string>

namespace udg {
	namespace eth {

		typedef h160 Address;
		using Bloom = FixedSizedByteArray<256>;
		using BlockNonce = FixedSizedByteArray<8>;

		struct Transaction : public rlp::RLPConvertable {
			FixedSizedByteArray<8> account_nonce;
			uint256 price;
			uint256 gas_limit;
			Address recipient;
			uint256 amount;
			std::vector<uint8_t> payload;
			uint8_t V;
			uint256 R;
			uint256 S;
			bool contract_creation;

			h256 hash() const;
			uint64_t size() const;
			Address from() const;
			crypto::Signature sig() const;
			h256 sig_hash() const;

			Transaction() = default;
			Transaction(const Transaction&) = default;
			Transaction& operator=(const Transaction&) = default;
			Transaction(const std::vector<rlp::RLPData>& from_rlp);

			bool validate() const;

			rlp::rlpvec to_rlp() const;
			std::string to_string() const;
		};

		struct Header : public rlp::RLPConvertable {
			h256 parent_hash;
			h256 uncle_hash;
			Address coinbase;
			h256 root;
			h256 tx_hash;
			h256 receipt_hash;
			Bloom bloom;
			uint256 difficulty;
			uint256 number;
			uint256 gas_limit;
			uint256 gas_used;
			uint256 time;
			std::vector<uint8_t> extra;
			h256 mix_digest;
			BlockNonce nonce;

			Header() = default;
			Header(const Header&) = default;
			Header& operator=(const Header&) = default;

			Header(const std::vector<rlp::RLPData>& from_rlp);

			bool validate() const;
			h256 hash_no_nonce() const;

			rlp::rlpvec to_rlp() const;
			std::string to_string() const;
		};

		struct Block : public rlp::RLPConvertable {
			Header header;
			std::vector<Header> uncles;

			std::vector<Transaction> transactions;

			h256 hash() const;
			uint64_t size() const;

			Block() = default;
			Block(const Block&) = default;
			Block& operator=(const Block&) = default;

			Block(const std::string& hex_rlp);
			Block(const uint8_t* rlp, size_t len);

			bool validate() const;

			rlp::rlpvec to_rlp() const;
			std::string to_string() const;

		private:
			void load_rlp(const rlp::rlpvec& rlp);
		};
	}
}

#endif //UDG_BLOCKCHAIN_HPP
