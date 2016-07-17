/*
 * rlpx_connect.cpp
 *
 *  Created on: Jul 16, 2016
 *      Author: nsamson
 */

#include "rlpx.hpp"
#include "ecc/uECC.h"
#include "../../udg_sec.h"
#include "../../udg_sec_t.h"
#include <sgx_tseal.h>
#include <sgx_tcrypto.h>
#include <stdlib.h>
#include <string.h>
#include <memory>
#include "../hex_encode.hpp"
#include "hmac.hpp"
#include <vector>
#include <iterator>
#include <algorithm>

#define ENCLAVE_KEY_FILE "rlpx_keys.dat"
#define KEY_PAIR_SIZE 64U + 32U

using namespace udg;
using namespace udg::crypto;

bool keys_loaded = false;
crypto::RLPxKeyPair enclave_pair;

crypto::RLPxKeyPair::RLPxKeyPair() {
}

crypto::RLPxKeyPair::RLPxKeyPair(const crypto::RLPxKeyPair& that) {
	this->priv_key = that.priv_key;
	this->pub_key = that.pub_key;
}

crypto::RLPxKeyPair& crypto::RLPxKeyPair::operator=(const RLPxKeyPair& that) {
	this->priv_key = that.priv_key;
	this->pub_key = that.pub_key;

	return *this;
}

int udg::crypto::load_or_gen_keys() {
	size_t hash_file_size;
	ocall_file_size(&hash_file_size, ENCLAVE_KEY_FILE);

	bool loaded_file = false;

	if (hash_file_size == 0) {
		ocall_debug("Could not find key file!");
	} else {
		if (hash_file_size > 0xFFFF) {
			ocall_debug("Hash file size seems suspicious... Regenerating.");
		} else {
			uint32_t l = 0;
			uint32_t key_dat_len = KEY_PAIR_SIZE;
			std::auto_ptr<uint8_t> key_file(new uint8_t[hash_file_size]);

			uint8_t key_data[KEY_PAIR_SIZE];
			sgx_status_t res = sgx_unseal_data((const sgx_sealed_data_t*) key_file.get(), nullptr, &l, key_data, &key_dat_len);

			if (res != SGX_SUCCESS) {
				ocall_debug("Key file data corrupted. Regenerating.");
			} else {
				loaded_file = true;
				memcpy(enclave_pair.pub_key.data(), key_data, sizeof(udg::crypto::RLPxPublicKey));
				memcpy(enclave_pair.priv_key.data(),
						key_data + sizeof(udg::crypto::RLPxPublicKey),
						sizeof(udg::crypto::RLPxPrivateKey));
				return 0;
			}
		}
	}

	if (!loaded_file) { // Need to generate new keys.
		int res = uECC_make_key(enclave_pair.pub_key.data(), enclave_pair.priv_key.data(), uECC_secp256k1());

		if (res != 0) {
			return -1;
		} else {
			uint8_t key_data[KEY_PAIR_SIZE];
			enclave_pair.dump_keys(key_data);

			uint32_t sealed_size = sgx_calc_sealed_data_size(0, KEY_PAIR_SIZE);

			std::auto_ptr<uint8_t> sealed_key_file(new uint8_t[sealed_size]);

			sgx_status_t res = sgx_seal_data(
					0,
					nullptr,
					KEY_PAIR_SIZE,
					key_data,
					sealed_size,
					(sgx_sealed_data_t*)sealed_key_file.get());

			int ret;

			if (res != SGX_SUCCESS) {
				ocall_debug("Could not encrypt key data. Failing...");
				return (int) res;
			} else {
				ocall_write_file(&ret, ENCLAVE_KEY_FILE, sealed_key_file.get(), sealed_size);
				keys_loaded = true;
				return ret;
			}
		}
	}

	throw; // Should never get here.
}

void udg::crypto::print_pub_key() {
	if (!keys_loaded) {
		int res = crypto::load_or_gen_keys();
		if (res != 0) {
			ocall_debug("Could not load keys. Ignore output.");
		}
	}

	std::string out = udg::hex_encode(enclave_pair.pub_key.data(), sizeof(crypto::RLPxPublicKey));
	ocall_print(out.c_str());
}

const crypto::RLPxKeyPair& udg::crypto::get_keys() {
	return enclave_pair;
}

void udg::crypto::RLPxKeyPair::dump_keys(uint8_t out[]) const {
	memcpy(out, this->pub_key.data(), RLPxPublicKey::size);
	memcpy(out + RLPxPublicKey::size, this->priv_key.data(), RLPxPrivateKey::size);
}

crypto::RLPxKeyPair udg::crypto::RLPxKeyPair::create_rand() {
	crypto::RLPxKeyPair out;
	uECC_make_key(out.pub_key.data(), out.priv_key.data(), uECC_secp256k1());
	return out;
}

udg::crypto::RLPxSession::RLPxSession(RLPxPublicKey node_id, uint32_t inet_addr, uint16_t port) : conn(inet_addr, port) {

	this->ephemeral_keys = RLPxKeyPair::create_rand();

	std::vector<uint8_t> authInitiator;

	uint8_t static_shared_secret[32] = {};
	uint8_t ephemeral_shared_secret[32] = {};

	ocall_debug("Generating static shared secret...");

	uECC_shared_secret(node_id.data(), enclave_pair.priv_key.data(), static_shared_secret, uECC_secp256k1());



}

// Following functions are copied from cpp-ethereum
std::vector<uint8_t> udg::crypto::eciesKDF(const crypto::RLPxSecret& sec, const uint8_t addl_data[],
        size_t addl_data_len, unsigned out_len) {

	sgx_sha_state_handle_t sha_handle;
	sgx_sha256_init(&sha_handle);

	uint32_t reps = ((out_len + 7) * 8) / (64 * 8);

	uint8_t ctr[4] = {0, 0, 0, 1};

	std::vector<uint8_t> key;

	for (unsigned i = 0; i <= reps; i++) {
		sgx_sha256_update(ctr, 4, sha_handle);
		sgx_sha256_update(sec.data(), RLPxSecret::size, sha_handle);
		sgx_sha256_update(addl_data, addl_data_len, sha_handle);

		uint8_t digest[32];
		sgx_sha256_get_hash(sha_handle, (sgx_sha256_hash_t *) digest);
		sgx_sha256_close(sha_handle);
		sgx_sha256_init(&sha_handle);

		std::copy(digest, digest + 32, std::back_insert_iterator<std::vector<uint8_t> >(key));

		if (++ctr[3] || ++ctr[2] || ++ctr[1] || ++ctr[0]) {
			continue;
		}

	}

	sgx_sha256_close(sha_handle);
	key.resize(out_len);

	return key;

}


void udg::crypto::encryptECIES(const RLPxPublicKey& pub, const uint8_t mac_data[], size_t mac_len, std::vector<uint8_t>& io) {
	auto r = crypto::RLPxKeyPair::create_rand();
	crypto::RLPxSecret z;

	uECC_shared_secret(pub.data(), r.priv_key.data(), z.data(), uECC_secp256k1());

	auto key = crypto::eciesKDF(z, {}, 0, 32);
	uint8_t eKey[16] = {};
	uint8_t mKeyMaterial[16] = {};
	std::copy(key.begin(), key.begin() + 16, eKey);
	std::copy(key.begin() + 16, key.begin() + 32, mKeyMaterial);

	sgx_sha_state_handle_t sha_handle;
	sgx_sha256_init(&sha_handle);

	sgx_sha256_update(mKeyMaterial, 16, sha_handle);

	uint8_t mKey[32] = {};
	sgx_sha256_get_hash(sha_handle, (sgx_sha256_hash_t*) mKey);
	sgx_sha256_close(sha_handle);

	h128 iv;
	udg::crypto::create_nonce(iv);
	std::vector<uint8_t> cipher_text;
	cipher_text.resize(io.size(), 0);
	h128 temp_iv(iv);

	sgx_status_t ret = sgx_aes_ctr_encrypt(
			(const sgx_aes_ctr_128bit_key_t*)eKey,
			(const unsigned char*) &io[0],
			(const uint32_t)io.size(),
			temp_iv.data(),
			1,
			(unsigned char*) &cipher_text[0]);

	if (ret != SGX_SUCCESS) {
		ocall_debug("Failed to encrypt.");
		printf("Return code: %d\n", (int) ret);
	}

	std::vector<uint8_t> msg(1 + sizeof(crypto::RLPxPublicKey) + sizeof(udg::h128) + cipher_text.size() + 32);
	msg[0] = 0x04;

	std::copy(r.pub_key.begin(), r.pub_key.begin() + sizeof(RLPxPublicKey), msg.begin() + 1);
	std::copy(iv.begin(), iv.end(), msg.begin() + 1 + sizeof(RLPxPublicKey));
	std::copy(cipher_text.begin(), cipher_text.end(), msg.begin() + 1 + sizeof(RLPxPublicKey) + h128::size);

	std::vector<uint8_t> civ(msg.begin() + 1 + sizeof(RLPxPublicKey), msg.begin() + 1 + sizeof(RLPxPublicKey) + h128::size + cipher_text.size());
	civ.insert(civ.end(), mac_data, mac_data + mac_len);

	h256 hmc = udg::crypto::hmac_sha256(mKey, 32, &civ[0], civ.size());
	std::copy(hmc.begin(), hmc.end(), msg.begin() + 1 + sizeof(RLPxPublicKey) + civ.size() - mac_len);

	io.resize(msg.size());
	io.swap(msg);

}

int udg::crypto::decryptECIES(const RLPxPrivateKey& priv, const uint8_t mac_data[], size_t mac_len, std::vector<uint8_t>& io) {
	if (io.empty() || io[0] < 2 || io[0] > 4) {
		return -1;
	}

	if (io.size() < (1 + sizeof(RLPxPublicKey) + h128::size + 1 + h256::size)) {
		return -2;
	}

	RLPxPrivateKey z;

	RLPxPublicKey from_io;
	std::copy(io.begin() + 1, io.begin() + 1 + RLPxPublicKey::size, from_io.begin());

	uECC_shared_secret(from_io.data(), priv.data(), z.data(), uECC_secp256k1());
	auto key = udg::crypto::eciesKDF(z, {}, 0, 64);

	h128 eKey(key.begin(), key.begin() + 16);
	h128 mKeyMaterial(key.begin() + 16, key.begin() + 32);
	h256 mKey;

	{
		sgx_sha_state_handle_t sha_handle;
		sgx_sha256_init(&sha_handle);
		sgx_sha256_update(mKeyMaterial.data(), h128::size, sha_handle);
		sgx_sha256_get_hash(sha_handle, (sgx_sha256_hash_t*) mKey.data());
		sgx_sha256_close(sha_handle);
	}

	std::vector<uint8_t> plain;
	size_t cipherLen = io.size() - 1 - RLPxPublicKey::size - h128::size - h256::size;

	std::vector<uint8_t> cipherWithIV(io.begin() + 1 + RLPxPublicKey::size,
			io.begin() + 1 + RLPxPublicKey::size + h128::size + cipherLen);
	h128 cipherIV(cipherWithIV.begin(), cipherWithIV.begin() + h128::size);
	std::vector<uint8_t> cipher_text(cipherWithIV.begin() + h128::size, cipherWithIV.end());

	{
		h256 mac(io.end() - 32, io.end());
		std::vector<uint8_t> hmac_data;
		hmac_data.insert(hmac_data.end(), cipherWithIV.begin(), cipherWithIV.end());
		hmac_data.insert(hmac_data.end(), mac_data, mac_data + mac_len);
		ocall_debug(hex_encode(std::string(hmac_data.begin(), hmac_data.end())).c_str());
		h256 hmac = udg::crypto::hmac_sha256(mKey.data(), h256::size, &hmac_data[0], hmac_data.size());

		if (hmac != mac) {
			ocall_debug(hmac.to_string().c_str());
			ocall_debug(mac.to_string().c_str());
			return -3;
		}
	}

	plain.resize(cipher_text.size(), 0);
	h128 temp_iv(cipherIV);

	sgx_aes_ctr_decrypt(
			(const sgx_aes_ctr_128bit_key_t*)eKey.data(),
			&cipher_text[0],
			cipher_text.size(),
			temp_iv.data(),
			1,
			&plain[0]
	);

	io.resize(plain.size());
	io.swap(plain);

	return 0;
}



