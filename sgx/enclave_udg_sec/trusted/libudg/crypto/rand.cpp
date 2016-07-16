/*
 * rand.cpp
 *
 *  Created on: Jul 16, 2016
 *      Author: nsamson
 */

#include "rand.hpp"
#include <sgx_trts.h>

void udg::crypto::create_nonce(udg::h128& out) {
	sgx_read_rand((unsigned char*)out, sizeof(udg::h128));
}

void udg::crypto::create_nonce(udg::h256& out) {
	sgx_read_rand((unsigned char*)out, sizeof(udg::h256));
}
