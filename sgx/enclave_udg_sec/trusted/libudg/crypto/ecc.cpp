/*
 * ecc.cpp
 *
 *  Created on: Jul 18, 2016
 *      Author: nsamson
 */


#include "ecc.hpp"
#include "../io.hpp"
#include "secp256k1/include/secp256k1_recovery.h"
#include "secp256k1/include/secp256k1_ecdh.h"

using namespace udg;
using namespace udg::crypto;

secp256k1_context* udg::crypto::secp_ctx(secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY));
static const PublicKey c_zeroKey("3f17f1962b36e491b30a40b2405849e597ba5fb5");

bool udg::crypto::SignatureStruct::isValid() const {
	return !(v > 3 ||
			r >= h256("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")||
			s >= h256("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141") ||
			s < h256("1") ||
			r < h256("1"));
}

PublicKey udg::crypto::recover(Signature const& _sig, h256 const& _message) {
	h520 o;
	int pklen;
	if (_sig[64] > 3 || !secp256k1_ecdsa_recover(secp_ctx, (secp256k1_pubkey *) o.data(),
			(const secp256k1_ecdsa_recoverable_signature *)_sig.data(), _message.data())) {
		io::cdebug << "Key recovery failed.";
		return PublicKey();
	}

	PublicKey out(o.begin() + 1, o.end());

	if (out == c_zeroKey) {
		io::cdebug << "Key recovery failed. Bad key?";
		return PublicKey();
	}

	return out;

}

PublicKey udg::crypto::SignatureStruct::recover(const h256& _hash) const {
	return udg::crypto::recover((Signature)*this, _hash);
}

Signature udg::crypto::sign(Secret const& k, h256 const& hash) {
	Signature s;
	SignatureStruct& ss = *reinterpret_cast<SignatureStruct*>(&s);

	if (!secp256k1_ecdsa_sign_recoverable(secp_ctx,
			(secp256k1_ecdsa_recoverable_signature *)s.data(),
			hash.data(),
			k.data(),
			nullptr,
			nullptr)) {
		io::cdebug << "Signing failed.";
		return Signature();
	}

	// Normalization is handled by secp256k1 library

	return s;

}


crypto::KeyPair::KeyPair() {
}

crypto::KeyPair::KeyPair(const crypto::KeyPair& that) {
	this->priv_key = that.priv_key;
	this->pub_key = that.pub_key;
}

crypto::KeyPair& crypto::KeyPair::operator=(const KeyPair& that) {
	this->priv_key = that.priv_key;
	this->pub_key = that.pub_key;

	return *this;
}

void udg::crypto::KeyPair::dump_keys(uint8_t out[]) const {
	memcpy(out, this->pub_key.data(), PublicKey::size);
	memcpy(out + PublicKey::size, this->priv_key.data(), PrivateKey::size);
}

crypto::KeyPair udg::crypto::KeyPair::create_rand() {
	crypto::KeyPair out;
	while (!secp256k1_ec_seckey_verify(secp_ctx, out.priv_key.data())) {
		io::cdebug << "Key verification failed. Failed key follows: "
				<< out.priv_key.to_string();
		out.priv_key = PrivateKey::random();
	}

	io::cdebug << "Key verification succeeded.";

	int ret = secp256k1_ec_pubkey_create(secp_ctx,
			(secp256k1_pubkey*)out.pub_key.data(),
			out.priv_key.data());

	if (ret == 0) {
		io::cdebug << "Create rand failed!";
		return KeyPair();
	}
	return out;
}

Secret udg::crypto::shared_secret(const PublicKey& pubk, const PrivateKey& privk) {
	Secret out;

	if (!secp256k1_ecdh(secp_ctx, out.data(), (secp256k1_pubkey*) pubk.data(), privk.data())) {
		io::cdebug << "Shared secret failed!";
		return Secret();
	}

	return out;
}

bool udg::crypto::verify(const PublicKey& pubk, const Signature& _sig, const h256& _message) {
	return secp256k1_ecdsa_verify(secp_ctx,(const secp256k1_ecdsa_signature*) _sig.data(), _message.data(),
			(const secp256k1_pubkey*)pubk.data()) == 1;
}
