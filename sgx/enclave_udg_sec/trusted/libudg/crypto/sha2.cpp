/*
 * sha2.cpp
 *
 *  Created on: Jul 18, 2016
 *      Author: nsamson
 */

#include "sha2.hpp"
#include "../io.hpp"

using namespace udg;
using namespace udg::crypto;

udg::crypto::sha256::sha256() {
	sgx_sha256_init(&this->sha_handle);
}

sha256& udg::crypto::sha256::operator <<(const std::string& str) {
	this->update(str.c_str(), str.length());
	return *this;
}

sha256& udg::crypto::sha256::operator <<(const std::vector<uint8_t>& bytes) {
	this->update(&bytes[0], bytes.size());
	return *this;
}

h256 udg::crypto::sha256::get_hash() {
	h256 out;
	sgx_sha256_get_hash(this->sha_handle, (sgx_sha256_hash_t *) out.data());
	return out;
}

void udg::crypto::sha256::get_hash(h256& out) {
	out = this->get_hash();
}

void udg::crypto::sha256::restart() {
	sgx_sha256_close(sha_handle);
	this->sha_handle = nullptr;
	sgx_sha256_init(&this->sha_handle);
}

udg::crypto::sha256::~sha256() {
	sgx_sha256_close(sha_handle);
}

void udg::crypto::sha256::operator>>(h256& out) {
	this->get_hash(out);
}
