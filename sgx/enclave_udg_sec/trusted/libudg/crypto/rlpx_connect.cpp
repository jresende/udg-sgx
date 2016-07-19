/*
 * rlpx_connect.cpp
 *
 *  Created on: Jul 16, 2016
 *      Author: nsamson
 */

#include "rlpx.hpp"
#include "../../udg_sec.h"
#include "../../udg_sec_t.h"
#include <sgx_tseal.h>
#include <sgx_tcrypto.h>
#include <stdlib.h>
#include <string.h>
#include <memory>
#include "../hex_encode.hpp"
#include "all_hash.hpp"
#include <vector>
#include <iterator>
#include <algorithm>
#include "../io.hpp"
#include "secp256k1/include/secp256k1_recovery.h"
#include "ecc.hpp"

#define ENCLAVE_KEY_FILE "rlpx_keys.dat"
#define KEY_PAIR_SIZE PublicKey::size + PrivateKey::size

using namespace udg;
using namespace udg::crypto;

bool keys_loaded = false;
crypto::KeyPair enclave_pair;

//secp256k1_context* udg::crypto::secp_ctx(secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY));

int udg::crypto::load_or_gen_keys() {

	if (keys_loaded) {
		return 0;
	}

	size_t hash_file_size;

	ocall_file_size(&hash_file_size, ENCLAVE_KEY_FILE);
	bool loaded_file = false;

	if (hash_file_size == 0) {
		io::cdebug.puts("Could not find key file!");
	} else {
		if (hash_file_size > 0xFFFF) {
			io::cdebug.puts("Hash file size seems suspicious... Regenerating.");
		} else {
			uint32_t l = 0;
			uint32_t key_dat_len = KEY_PAIR_SIZE;
			std::auto_ptr<uint8_t> key_file(new uint8_t[hash_file_size]);

			int r;
			ocall_read_file(&r, ENCLAVE_KEY_FILE, key_file.get(), hash_file_size);

			uint8_t key_data[KEY_PAIR_SIZE];
			sgx_status_t res = sgx_unseal_data((const sgx_sealed_data_t*) key_file.get(), nullptr, &l, key_data, &key_dat_len);

			if (r != 0 || res != SGX_SUCCESS) {
				io::cdebug.puts("Key file data corrupted. Regenerating.");
				printf("%d\n", (int) res);
			} else {
				loaded_file = true;
				memcpy(enclave_pair.pub_key.data(), key_data, sizeof(udg::crypto::PublicKey));
				memcpy(enclave_pair.priv_key.data(),
						key_data + sizeof(udg::crypto::PublicKey),
						sizeof(udg::crypto::PrivateKey));
				return 0;
			}
		}
	}

	if (!loaded_file) { // Need to generate new keys.
		enclave_pair = KeyPair::create_rand();


		io::cdebug.puts("1");
		uint8_t key_data[KEY_PAIR_SIZE];
		enclave_pair.dump_keys(key_data);
		io::cdebug.puts("2");
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
			io::cdebug.puts("Could not encrypt key data. Failing...");
			return (int) res;
		} else {
			ocall_write_file(&ret, ENCLAVE_KEY_FILE, sealed_key_file.get(), sealed_size);
			keys_loaded = true;
			return ret;
		}

	}

	throw; // Should never get here.
}

void udg::crypto::print_pub_key() {
	if (!keys_loaded) {
		int res = crypto::load_or_gen_keys();
		if (res != 0) {
			io::cdebug.puts("Could not load keys. Ignore output.");
		}
	}

	std::string out = udg::hex_encode(enclave_pair.pub_key.data(), sizeof(crypto::PublicKey));
	io::cout.puts(out.c_str());
}

const crypto::KeyPair& udg::crypto::get_keys() {
	load_or_gen_keys();
	return enclave_pair;
}

udg::crypto::RLPxSession::RLPxSession(PublicKey node_id, uint32_t inet_addr, uint16_t port) : conn(inet_addr, port) {

	load_or_gen_keys();
	this->ephemeral_keys = KeyPair::create_rand();
	this->dest = node_id;

	int r = this->sendAuth();
	if (r != 0) {
		goto err;
	}

	r = this->recvAck();
	if (r != 0) {
		goto err;
	}

	err:
	io::cout << "Something went horribly wrong!\n";

}

int udg::crypto::RLPxSession::sendAuth() {

	create_nonce(nonce);

	io::cdebug.puts("Generating static shared secret...");

//	uECC_shared_secret(this->dest.data(), enclave_pair.priv_key.data(), static_shared_secret.data(), uECC_secp256k1());
	static_shared_secret = crypto::shared_secret(dest, enclave_pair.priv_key);

	h256 xord_static_nonce = static_shared_secret ^ nonce;

	Signature signature;

//	uECC_sign(this->ephemeral_keys.priv_key.data(), xord_static_nonce.data(), h256::size, signature.data(), uECC_secp256k1());
	secp256k1_ecdsa_sign_recoverable(secp_ctx,
			(secp256k1_ecdsa_recoverable_signature *)signature.data(),
			xord_static_nonce.data(),
			this->ephemeral_keys.priv_key.data(),
			NULL,
			NULL
	);

	io::cdebug << "Signature: " << signature.to_string();

	authInitiator.insert(authInitiator.end(), signature.begin(), signature.end());
	h256 hepubk;

	keccak256 ctxt;

	ctxt.update(this->ephemeral_keys.pub_key.data(), h512::size);
	ctxt.finalize();

	ctxt.get_digest(hepubk.data());

	authInitiator.insert(authInitiator.end(), hepubk.begin(), hepubk.end());
	authInitiator.insert(authInitiator.end(), get_keys().pub_key.begin(), get_keys().pub_key.end());
	authInitiator.insert(authInitiator.end(), nonce.begin(), nonce.end());
	authInitiator.push_back(0);

	io::cdebug << "Encrypting authInit";
	io::cdebug << authInitiator.size();
	io::cdebug << signature.to_string().c_str();

	encryptECIES(this->dest, {}, 0, authInitiator);

	io::cdebug << authInitiator.size();

	int r = this->conn.send(&authInitiator[0], authInitiator.size(), 0x100);
	io::cdebug << "Send returned: " << r;

	return (r == authInitiator.size()) ? 0 : -1;
}

int udg::crypto::RLPxSession::recvAck() {
	std::vector<uint8_t> ack_cipher(210);

	io::cdebug << "Waiting for ack data...";

	int r = 0;
	int total_recv = 0;
	int to_recv = 210;
	while (to_recv > 0) {
		if ((r = this->conn.recv(&ack_cipher[total_recv], to_recv, 0x100)) < 1) {
			io::cout << "Connection terminated by peer or timeout occurred.\n";
			return -2;
		}
		to_recv -= r;
		total_recv += r;
	}

	io::cdebug << "Recv ret: " << r;
	io::cdebug << "Received ack data." << ack_cipher.size();
	io::cdebug << hex_encode(&ack_cipher[0], ack_cipher.size());


	if ((r = decryptECIES(get_keys().priv_key, {}, 0, ack_cipher)) != 0) {
		io::cdebug << r;
		return -3;
	}

	io::cdebug << "Decrypted message";

	PublicKey remote_pub_ephem(ack_cipher.begin(), ack_cipher.begin() + PublicKey::size);
	this->remote_nonce = h256(
			ack_cipher.begin() + PublicKey::size,
			ack_cipher.begin() + PublicKey::size + h256::size
	);

//	uECC_shared_secret(remote_pub_ephem.data(), this->ephemeral_keys.priv_key.data(),
//			this->ephemeral_shared_secret.data(), uECC_secp256k1());
	ephemeral_shared_secret = crypto::shared_secret(
			remote_pub_ephem,
			this->ephemeral_keys.priv_key);

	keccak256 ctxt;
	ctxt.update(this->nonce.data(), h256::size);
	ctxt.update(this->remote_nonce.data(), h256::size);

	h256 intermed;
	ctxt.finalize();
	ctxt.get_digest(intermed.data());

	ctxt = keccak256();
	ctxt.update(this->ephemeral_shared_secret.data(), h256::size);
	ctxt.update(intermed.data(), h256::size);
	ctxt.finalize();
	ctxt.get_digest(this->shared_secret.data());

	// Don't care about token right now.

	ctxt = keccak256();
	ctxt.update(this->ephemeral_shared_secret.data(), h256::size);
	ctxt.update(this->shared_secret.data(), h256::size);
	ctxt.finalize();
	ctxt.get_digest(this->aes_secret.data());

	this->shared_secret.clear();

	ctxt = keccak256();
	ctxt.update(this->ephemeral_shared_secret.data(), h256::size);
	ctxt.update(this->aes_secret.data(), h256::size);
	ctxt.finalize();
	ctxt.get_digest(this->mac_secret.data());

	this->ephemeral_shared_secret.clear();

	ctxt = keccak256();
	ctxt.update((this->mac_secret ^ this->nonce).data(), h256::size);
	ctxt.update(&this->authInitiator[0], authInitiator.size());
	ctxt.finalize();
	ctxt.get_digest(this->egress_mac.data());

	this->nonce.clear();

	ctxt = keccak256();
	ctxt.update((this->mac_secret ^ this->remote_nonce).data(), h256::size);
	ctxt.update(&ack_cipher[0], ack_cipher.size());
	ctxt.finalize();
	ctxt.get_digest(this->ingress_mac.data());

	io::cdebug << "Successfully completed handshake with " << this->dest.to_string() << "\n";

	return 0;

}

// Following functions are copied from cpp-ethereum
std::vector<uint8_t> udg::crypto::eciesKDF(const crypto::Secret& sec, const uint8_t addl_data[],
        size_t addl_data_len, unsigned out_len) {

	sha256 ctx;

	uint32_t reps = ((out_len + 7) * 8) / (64 * 8);
	io::cdebug << __FUNCTION__ << reps;

	uint8_t ctr[4] = {0, 0, 0, 1};

	std::vector<uint8_t> key;

	for (unsigned i = 0; i <= reps; i++) {
		ctx.update(ctr, 4);
		ctx << sec;
		ctx.update(addl_data, addl_data_len);

		h256 digest;
		ctx >> digest;
		ctx.restart();

		std::copy(digest.begin(),
				digest.end(), std::back_insert_iterator<std::vector<uint8_t> >(key));

		if (++ctr[3] || ++ctr[2] || ++ctr[1] || ++ctr[0]) {
			continue;
		}

	}

	key.resize(out_len);

	return key;

}

void udg::crypto::encryptECIES(const PublicKey& pub, const uint8_t mac_data[], size_t mac_len, std::vector<uint8_t>& io) {
	auto r = crypto::KeyPair::create_rand();
	crypto::Secret z;

//	uECC_shared_secret(pub.data(), r.priv_key.data(), z.data(), uECC_secp256k1());
	z = crypto::shared_secret(pub, r.priv_key);
	io::cdebug << "Shared secret encrypt: " << z.to_string();

	auto key = crypto::eciesKDF(z, {}, 0, 32);
	h128 eKey;
	h128 mKeyMaterial;
	std::copy(key.begin(), key.begin() + 16, eKey.begin());
	std::copy(key.begin() + 16, key.begin() + 32, mKeyMaterial.begin());

	h256 mKey;

	sha256 ctx;
	ctx << mKeyMaterial >> mKey;

	h128 iv;
//	udg::crypto::create_nonce(iv);
	std::vector<uint8_t> cipher_text;
	cipher_text.resize(io.size(), 0);
	h128 temp_iv(iv);

	sgx_status_t ret = sgx_aes_ctr_encrypt(
			(const sgx_aes_ctr_128bit_key_t*)eKey.data(),
			(const unsigned char*) &io[0],
			(const uint32_t)io.size(),
			temp_iv.data(),
			1,
			(unsigned char*) &cipher_text[0]);

	if (ret != SGX_SUCCESS) {
		io::cdebug.puts("Failed to encrypt.");
		printf("Return code: %d\n", (int) ret);
	}

	std::vector<uint8_t> msg(1 + sizeof(crypto::PublicKey) + sizeof(udg::h128) + cipher_text.size() + 32);
	msg[0] = 0x04;

	std::copy(r.pub_key.begin(), r.pub_key.begin() + sizeof(PublicKey), msg.begin() + 1);
	std::copy(iv.begin(), iv.end(), msg.begin() + 1 + sizeof(PublicKey));
	std::copy(cipher_text.begin(), cipher_text.end(), msg.begin() + 1 + sizeof(PublicKey) + h128::size);

	std::vector<uint8_t> civ(msg.begin() + 1 + sizeof(PublicKey), msg.begin() + 1 + sizeof(PublicKey) + h128::size + cipher_text.size());
	civ.insert(civ.end(), mac_data, mac_data + mac_len);

	io::cdebug << "Encrypt mKey data: " << mKey.to_string();

	h256 hmc = udg::crypto::hmac_sha256(mKey.data(), h256::size, &civ[0], civ.size());

	io::cdebug << "Encrypt HMAC data: " << hex_encode(&civ[0], civ.size());
	io::cdebug << "Encrypt HMAC: " << hmc.to_string();
	std::copy(hmc.begin(), hmc.end(), msg.begin() + 1 + sizeof(PublicKey) + civ.size() - mac_len);

	io.resize(msg.size());
	io.swap(msg);

}

int udg::crypto::decryptECIES(const PrivateKey& priv, const uint8_t mac_data[], size_t mac_len, std::vector<uint8_t>& io) {
	if (io.empty() || io[0] < 2 || io[0] > 4) {
		io::cdebug << (int) io[0];
		return -1;
	}

	if (io.size() < (1 + sizeof(PublicKey) + h128::size + 1 + h256::size)) {
		return -2;
	}

	Secret z;

	PublicKey from_io;
	std::copy(io.begin() + 1, io.begin() + 1 + PublicKey::size, from_io.begin());

//	uECC_shared_secret(from_io.data(), priv.data(), z.data(), uECC_secp256k1());
	z = crypto::shared_secret(from_io, priv);

	io::cdebug << "Shared secret decrypt: " << z.to_string();
	auto key = udg::crypto::eciesKDF(z, {}, 0, 64);

	h128 eKey(key.begin(), key.begin() + 16);
	h128 mKeyMaterial(key.begin() + 16, key.begin() + 32);
	h256 mKey;

	{
		sha256 ctx;
		ctx << mKeyMaterial >> mKey;
	}

	io::cdebug << "Decrypt mKey: " << mKey.to_string();

	std::vector<uint8_t> plain;
	size_t cipherLen = io.size() - 1 - PublicKey::size - h128::size - h256::size;

	std::vector<uint8_t> cipherWithIV(io.begin() + 1 + PublicKey::size,
			io.begin() + 1 + PublicKey::size + h128::size + cipherLen);
	h128 cipherIV(cipherWithIV.begin(), cipherWithIV.begin() + h128::size);
	std::vector<uint8_t> cipher_text(cipherWithIV.begin() + h128::size, cipherWithIV.end());

	{
		h256 mac(io.end() - 32, io.end());
		std::vector<uint8_t> hmac_data;
		hmac_data.insert(hmac_data.end(), cipherWithIV.begin(), cipherWithIV.end());
		hmac_data.insert(hmac_data.end(), mac_data, mac_data + mac_len);
		io::cdebug.puts(hex_encode(std::string(hmac_data.begin(), hmac_data.end())).c_str());
		h256 hmac = udg::crypto::hmac_sha256(mKey.data(), h256::size, &hmac_data[0], hmac_data.size());

		if (hmac != mac) {
			io::cdebug << "Decrypt HMAC data: " << hex_encode(&hmac_data[0], hmac_data.size());
			io::cdebug << "Mac comparison failed: ";
			io::cdebug.puts(hmac.to_string().c_str());
			io::cdebug.puts(mac.to_string().c_str());
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

ssize_t udg::crypto::RLPxSession::send(const void* buf, size_t len) {
	throw;
}

ssize_t udg::crypto::RLPxSession::recv(void* buf, size_t len) {
	throw;
}
