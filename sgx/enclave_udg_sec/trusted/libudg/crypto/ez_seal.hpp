/*
 * ex_seal.hpp
 *
 *  Created on: Sep 14, 2016
 *      Author: nsamson
 */

#ifndef SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_CRYPTO_EZ_SEAL_HPP_
#define SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_CRYPTO_EZ_SEAL_HPP_

#include <sgx_tseal.h>
#include <stdint.h>
#include <vector>

namespace udg {
	namespace crypto {
		std::vector<uint8_t> seal_data(const uint8_t* data, uint32_t len);
		std::vector<uint8_t> unseal_data(const uint8_t* data, uint32_t unsealed_len);

		class data_integrity_exception : public std::runtime_error {
		public:
			data_integrity_exception() : std::runtime_error("Data integrity failure") {}
		};
	}
}

inline std::vector<uint8_t> udg::crypto::seal_data(const uint8_t* data,
        uint32_t len) {

	uint32_t out_size = sgx_calc_sealed_data_size(0, len);

	std::vector<uint8_t> out;
	out.resize(out_size);

	auto res = sgx_seal_data(0, nullptr, len, data, out_size, (sgx_sealed_data_t*)(&out[0]));

	if (res != SGX_SUCCESS) {
		throw udg::crypto::data_integrity_exception();
	}

	return out;

}

inline std::vector<uint8_t> udg::crypto::unseal_data(const uint8_t* data, uint32_t unsealed_len) {

	std::vector<uint8_t> out;
	out.resize(unsealed_len);
	uint32_t z = 0;

	auto res = sgx_unseal_data((sgx_sealed_data_t*)data, nullptr, &z, &out[0], &unsealed_len);

	if (res != SGX_SUCCESS) {
		throw udg::crypto::data_integrity_exception();
	}

	return out;

}

#endif /* SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_CRYPTO_EZ_SEAL_HPP_ */
