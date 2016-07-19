/*
 * time.hpp
 *
 *  Created on: Jul 18, 2016
 *      Author: nsamson
 */

#ifndef SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_TIME_HPP_
#define SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_TIME_HPP_

#include <sgx_tae_service.h>
#include <stdexcept>

namespace udg {

	namespace err {
		class time_nonce_changed : public std::runtime_error {

			sgx_time_source_nonce_t old_nonce;
			sgx_time_source_nonce_t new_nonce;

		public:

			time_nonce_changed(const sgx_time_source_nonce_t& old, const sgx_time_source_nonce_t& _new);

		};
	}
	uint64_t get_time();
}



#endif /* SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_TIME_HPP_ */
