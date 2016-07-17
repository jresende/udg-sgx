/*
 * hmac.hpp
 *
 *  Created on: Jul 16, 2016
 *      Author: nsamson
 */

#ifndef SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_CRYPTO_HMAC_HPP_
#define SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_CRYPTO_HMAC_HPP_

#include <stdint.h>
#include "../byte_array.hpp"

namespace udg {
	namespace crypto {

		h256 hmac_sha256(const uint8_t key[], size_t key_len, const uint8_t data[], size_t len);

	}
}



#endif /* SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_CRYPTO_HMAC_HPP_ */
