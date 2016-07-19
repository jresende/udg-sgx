/*
 * sha2.hpp
 *
 *  Created on: Jul 18, 2016
 *      Author: nsamson
 */

#ifndef SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_CRYPTO_SHA2_HPP_
#define SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_CRYPTO_SHA2_HPP_

#include <stdint.h>
#include <sgx_tcrypto.h>
#include "../byte_array.hpp"
#include <algorithm>

namespace udg {
	namespace crypto {

		class sha256 {

			sgx_sha_state_handle_t sha_handle;

		public:

			sha256();
			sha256(const sha256&) = delete;
			sha256(sha256&& mv) = default;

			sha256& operator=(const sha256&) = delete;
			sha256& operator=(sha256&&) = default;

			sha256& operator<<(const std::string& str);
			sha256& operator<<(const std::vector<uint8_t>& bytes);

			template <unsigned long int N>
			sha256& operator<<(const FixedSizedByteArray<N>& h) {
				return this->update(h.data(), N);
			}

			template <typename T>
			sha256& update(const T& ptr, size_t len) {
				sgx_sha256_update((const uint8_t *)ptr, len, this->sha_handle);
				return *this;
			}

			void operator>>(h256& out);

			h256 get_hash();
			void get_hash(h256&);

			void restart();

			~sha256();

		};

		template <typename T>
		h256 sha256_msg(const T& ptr, size_t len) {
			h256 out;
			sgx_sha256_msg((const uint8_t*)ptr, len, (sgx_sha256_hash_t*)out.data());
			return out;
		}

	}
}



#endif /* SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_CRYPTO_SHA2_HPP_ */
