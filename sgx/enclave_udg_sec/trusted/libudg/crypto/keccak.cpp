//
// Created by nsamson on 7/12/16.
//


#include "keccak.hpp"
#include <algorithm>
#include "../hex_encode.hpp"

udg::crypto::keccak256::keccak256() {
    sha3_Init256(&this->ctxt);
}

void udg::crypto::keccak256::update(const uint8_t *buf, size_t len) {
    sha3_Update(&this->ctxt, buf, len);
}

void udg::crypto::keccak256::update(const std::string &msg) {
    this->update((const uint8_t *) msg.c_str(), msg.length());
}

void udg::crypto::keccak256::finalize() {
    sha3_Finalize(&this->ctxt);
}

void udg::crypto::keccak256::get_digest(uint8_t *buf) const {
    std::copy(this->ctxt.sb, this->ctxt.sb + 32, buf);
}

void udg::crypto::keccak384::get_digest(uint8_t *buf) const {
    std::copy(this->ctxt.sb, this->ctxt.sb + 32, buf);
}

void udg::crypto::keccak512::get_digest(uint8_t *buf) const {
    std::copy(this->ctxt.sb, this->ctxt.sb + 32, buf);
}

void udg::crypto::keccak384::finalize() {
    sha3_Finalize(&this->ctxt);
}

void udg::crypto::keccak512::finalize() {
    sha3_Finalize(&this->ctxt);
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
}

udg::crypto::keccak512::keccak512() {
    sha3_Init512(&this->ctxt);
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

