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

using namespace udg;
using namespace udg::crypto;

int ecall_udg_test_ECIES() {

	RLPxKeyPair kp1 = RLPxKeyPair::create_rand();
	RLPxKeyPair kp2 = RLPxKeyPair::create_rand();

	std::string kp1_pub = hex_encode(kp1.pub_key.data(), RLPxPublicKey::size);
	std::string kp1_priv = hex_encode(kp1.priv_key.data(), RLPxPrivateKey::size);

	std::string kp2_pub = hex_encode(kp2.pub_key.data(), RLPxPublicKey::size);
	std::string kp2_priv = hex_encode(kp2.priv_key.data(), RLPxPrivateKey::size);

	printf("PubKey1:  %s\n", kp1_pub.c_str());
	printf("PrivKey1: %s\n", kp1_priv.c_str());

	printf("\nPubKey2:  %s\n", kp2_pub.c_str());
	printf("PrivKey2: %s\n", kp2_priv.c_str());

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

	return 0;
}
