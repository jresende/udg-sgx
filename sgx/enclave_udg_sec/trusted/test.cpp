/*
 * test.cpp
 *
 *  Created on: Jul 16, 2016
 *      Author: nsamson
 */

#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "udg_sec.h"
#include "udg_sec_t.h"  /* print_string */
#include "libudg/crypto/rlpx.hpp"
#include "libudg/hex_encode.hpp"
#include "libudg/io.hpp"
#include "libudg/crypto/ecc/uECC.h"
#include "libudg/crypto/secp256k1/include/secp256k1_recovery.h"
#include "libudg/crypto/secp256k1/include/secp256k1.h"
#include <stdint.h>
#include <sgx_tcrypto.h>

using namespace udg;
using namespace udg::crypto;

int ecall_udg_test_ECIES() {
#ifndef NDEBUG
	udg::crypto::load_or_gen_keys();
	const KeyPair& kp1 = udg::crypto::get_keys();

	std::string kp1_pub = hex_encode(kp1.pub_key.data(), PublicKey::size);
	std::string kp1_priv = hex_encode(kp1.priv_key.data(), PrivateKey::size);

	printf("PubKey1:  %s\n", kp1_pub.c_str());
	printf("PrivKey1: %s\n", kp1_priv.c_str());

	std::string h = "Hello, world!";

	printf("Encrypting: %s\n", h.c_str());

	std::vector<uint8_t> io(h.begin(), h.end());

	encryptECIES(kp1.pub_key, {}, 0, io);

	std::string encrypted_data = hex_encode(&io[0], io.size());

	printf("Return code for decrypt: %d\n", decryptECIES(kp1.priv_key, {}, 0, io));

	std::string decrypted_data(io.begin(), io.end());

	printf("Decrypted string is: %s\n", decrypted_data.c_str());

	decrypted_data = hex_encode(&io[0], io.size());
	printf("Encrypted string (hex): %s\n", encrypted_data.c_str());
	printf("Decrypted string (hex): %s\n", decrypted_data.c_str());

	if (encrypted_data.compare(decrypted_data) != 0) {
		return -1;
	}

	secp256k1_context* c = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
	io::cdebug << "Verify key" << secp256k1_ec_seckey_verify(c, kp1.priv_key.data());

#endif

	return 0;
}

int ecall_udg_test_RLPxHandshake() {

	io::cdebug << "RLPxHandshake Test";

#ifndef NDEBUG
	udg::crypto::load_or_gen_keys();

	io::cdebug << "Loaded keys...";

	std::string local_node = "e76d49abcf53d9530759fcff3083176d4507fcd605d7128508389f43c35897a956f155f945c83b268a5dd7157edf5ea9496538e319144f7ba9d0cb3c81477f3c";
	auto local_node_bytes = hex_decode(local_node);
	PublicKey node_id(local_node_bytes.begin(), local_node_bytes.end());

	io::cdebug << "Node ID loaded.";

	std::string local_ip = "192.168.0.2";
	uint32_t ip_addr = ip_addr_str_to_int(local_ip);
	printf("%08X\n", ip_addr);

	uint16_t port = 30303;

	RLPxSession rlpx(node_id, ip_addr, port);

	io::cdebug << "Made it!";
#endif

	return 0;
}
