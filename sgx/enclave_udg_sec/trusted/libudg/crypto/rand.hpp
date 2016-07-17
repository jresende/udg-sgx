/*
 * rand.hpp
 *
 *  Created on: Jul 16, 2016
 *      Author: nsamson
 */

#ifndef SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_CRYPTO_RAND_HPP_
#define SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_CRYPTO_RAND_HPP_

#include <stdint.h>
#include <sgx_trts.h>
#include "../byte_array.hpp"

namespace udg {

	namespace crypto {
		template <unsigned long int N>
		void create_nonce(FixedSizedByteArray<N>& out) {
			sgx_read_rand(out.data(), FixedSizedByteArray<N>::size);
		}
	}
}


#endif /* SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_CRYPTO_RAND_HPP_ */
