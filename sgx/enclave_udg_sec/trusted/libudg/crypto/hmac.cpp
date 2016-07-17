/*
 * hmac.cpp
 *
 *  Created on: Jul 16, 2016
 *      Author: nsamson
 */

#include "hmac.hpp"
#include <sgx_tcrypto.h>
#include <algorithm>
#include <vector>

using namespace udg;
using namespace udg::crypto;

const h512 opad = h512(0x5c);
const h512 ipad = h512(0x36);

h256 udg::crypto::hmac_sha256(const uint8_t key[], size_t key_len, const uint8_t data[], size_t len) {
	h256 out;

	h512 block;

	if (key_len > h512::size) {
		sgx_sha_state_handle_t sha_handle;
		sgx_sha256_init(&sha_handle);
		sgx_sha256_update(key, key_len, sha_handle);
		sgx_sha256_get_hash(sha_handle, (sgx_sha256_hash_t*) block.data());
		sgx_sha256_close(sha_handle);

		key_len = h256::size;
	} else {
		std::copy(key, key + key_len, block.begin());
	}

	h512 o_key_pad = opad ^ block;
	h512 i_key_pad = ipad ^ block;

	std::vector<uint8_t> h;

	h.insert(h.end(), i_key_pad.begin(), i_key_pad.end());
	h.insert(h.end(), data, data + len);

	{
		sgx_sha_state_handle_t sha_handle;
		sgx_sha256_init(&sha_handle);
		sgx_sha256_update(&h[0], h.size(), sha_handle);
		sgx_sha256_get_hash(sha_handle, (sgx_sha256_hash_t*) out.data());
		sgx_sha256_close(sha_handle);
	}

	h.clear();

	h.insert(h.end(), o_key_pad.begin(), o_key_pad.end());
	h.insert(h.end(), out.begin(), out.end());

	{
		sgx_sha_state_handle_t sha_handle;
		sgx_sha256_init(&sha_handle);
		sgx_sha256_update(&h[0], h.size(), sha_handle);
		sgx_sha256_get_hash(sha_handle, (sgx_sha256_hash_t*) out.data());
		sgx_sha256_close(sha_handle);
	}

	return out;
}


