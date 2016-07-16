/*
 * rand.hpp
 *
 *  Created on: Jul 16, 2016
 *      Author: nsamson
 */

#ifndef SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_CRYPTO_RAND_HPP_
#define SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_CRYPTO_RAND_HPP_


namespace udg {

	typedef uint8_t h256[32];
	typedef uint8_t h128[16];

	namespace crypto {
		void create_nonce(h128& out);
		void create_nonce(h256& out);
	}
}


#endif /* SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_CRYPTO_RAND_HPP_ */
