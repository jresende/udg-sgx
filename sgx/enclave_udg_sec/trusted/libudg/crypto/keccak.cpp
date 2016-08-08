//
// Created by nsamson on 7/12/16.
//


#include "keccak.hpp"
#include <algorithm>
#include "../hex_encode.hpp"

using namespace udg;

udg::crypto::keccak256::keccak256() {
    sha3_Init256(&this->ctxt);
    this->finalized = false;
}

void udg::crypto::keccak256::update(const uint8_t *buf, size_t len) {
    sha3_Update(&this->ctxt, buf, len);
}

void udg::crypto::keccak256::update(const std::string &msg) {
    this->update((const uint8_t *) msg.c_str(), msg.length());
}

void udg::crypto::keccak256::finalize() {
    sha3_Finalize(&this->ctxt);
    this->finalized = true;
}

void udg::crypto::keccak256::get_digest(uint8_t *buf) const {
	if (!this->finalized) {
		throw crypto::keccak_not_finalized();
	}
    std::copy(this->ctxt.sb, this->ctxt.sb + 32, buf);
}

void udg::crypto::keccak384::get_digest(uint8_t *buf) const {
	if (!this->finalized) {
		throw crypto::keccak_not_finalized();
	}
    std::copy(this->ctxt.sb, this->ctxt.sb + 48, buf);
}

void udg::crypto::keccak512::get_digest(uint8_t *buf) const {
	if (!this->finalized) {
		throw crypto::keccak_not_finalized();
	}
    std::copy(this->ctxt.sb, this->ctxt.sb + 64, buf);
}

void udg::crypto::keccak384::finalize() {
    sha3_Finalize(&this->ctxt);
    this->finalized = true;
}

void udg::crypto::keccak512::finalize() {
    sha3_Finalize(&this->ctxt);
    this->finalized = true;
}

void udg::crypto::keccak384::update(const std::string &msg) {
    this->update((const uint8_t *) msg.c_str(), msg.length());
}

void udg::crypto::keccak512::update(const std::string &msg) {
    this->update((const uint8_t *) msg.c_str(), msg.length());
}

void udg::crypto::keccak384::update(const uint8_t *buf, size_t len) {
    sha3_Update(&this->ctxt, buf, len);
}

void udg::crypto::keccak512::update(const uint8_t *buf, size_t len) {
    sha3_Update(&this->ctxt, buf, len);
}


udg::crypto::keccak384::keccak384() {
    sha3_Init384(&this->ctxt);
    this->finalized = false;
}

udg::crypto::keccak512::keccak512() {
    sha3_Init512(&this->ctxt);
    this->finalized = false;
}


std::string udg::crypto::digest_str(const udg::crypto::keccak256 & hash) {
    uint8_t hash_bytes[32] = {};
    hash.get_digest(hash_bytes);
    return udg::hex_encode(hash_bytes, 32);
}

std::string udg::crypto::digest_str(const keccak384 & hash) {
    uint8_t hash_bytes[48] = {};
    hash.get_digest(hash_bytes);
    return udg::hex_encode(hash_bytes, 48);
}

std::string udg::crypto::digest_str(const keccak512 & hash) {
    uint8_t hash_bytes[64] = {};
    hash.get_digest(hash_bytes);
    return udg::hex_encode(hash_bytes, 64);
}

udg::h256 udg::crypto::rlp_keccak256(const udg::rlp::RLPConvertable& conv) {
	udg::rlp::rlpvec rlp = conv.to_rlp();
	udg::crypto::keccak256 ctxt;
	ctxt.update(&rlp[0], rlp.size());
	ctxt.finalize();
	udg::h256 out;
	ctxt.get_digest(out.data());

	return out;
}

h256 udg::crypto::keccak256::get_digest() const {
	h256 out;
	this->get_digest(out.data());
	return out;
}

h384 udg::crypto::keccak384::get_digest() const {
	h384 out;
	this->get_digest(out.data());
	return out;
}

h512 udg::crypto::keccak512::get_digest() const {
	h512 out;
	this->get_digest(out.data());
	return out;
}
