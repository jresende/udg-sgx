/*
 * ecc.hpp
 *
 *  Created on: Jul 18, 2016
 *      Author: nsamson
 */

#ifndef SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_CRYPTO_ECC_HPP_
#define SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_CRYPTO_ECC_HPP_

#include <stdint.h>
#include <algorithm>
#include "secp256k1/include/secp256k1_recovery.h"
#include "../byte_array.hpp"

namespace udg {
	namespace crypto {

		extern secp256k1_context* secp_ctx;

		typedef h512 PublicKey;
		typedef h256 PrivateKey;
		typedef h256 Secret;
		using Signature = FixedSizedByteArray<65>;

		struct SignatureStruct
		{
			SignatureStruct() = default;
			SignatureStruct(Signature const& _s): r(_s.begin(), _s.begin() + 32),
					s(_s.begin() + 32, _s.begin() + 64),
					v(_s[64]) {  }
			SignatureStruct(h256 const& _r, h256 const& _s, uint8_t _v): r(_r), s(_s), v(_v) {}
			operator Signature() const {
				Signature out;
				std::copy(r.begin(), r.end(), out.begin());
				std::copy(s.begin(), s.end(), out.begin() + 32);
				out[64] = v;
				return out;
			}

			/// @returns true if r,s,v values are valid, otherwise false
			bool isValid() const;

			/// @returns the public part of the key that signed @a _hash to give this sig.
			PublicKey recover(h256 const& _hash) const;

			h256 r;
			h256 s;
			uint8_t v = 0;
		};

		PublicKey recover(Signature const& _sig, h256 const& _message);
		Signature sign(Secret const& k, h256 const& hash);

		struct KeyPair {
			PublicKey pub_key;
			PrivateKey priv_key;

			static KeyPair create_rand();
			static KeyPair create_enclave_pair();

			KeyPair();
			KeyPair(const KeyPair& that);

			KeyPair& operator=(const KeyPair& that);

			void dump_keys(uint8_t out[]) const;
		};

		Secret shared_secret(const PublicKey& pubk, const PrivateKey& privk);

		bool verify(const PublicKey& pubk, Signature const& _sig, h256 const& _message);
	}
}



#endif /* SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_CRYPTO_ECC_HPP_ */
