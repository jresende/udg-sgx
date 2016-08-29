/*
 * keys.hpp
 *
 *  Created on: Aug 29, 2016
 *      Author: nsamson
 */

#ifndef SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_CRYPTO_KEYS_HPP_
#define SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_CRYPTO_KEYS_HPP_

#include "ecc.hpp"

namespace udg {
	namespace crypto {
		KeyPair get_unique_keys();
	}
}


#endif /* SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_CRYPTO_KEYS_HPP_ */
