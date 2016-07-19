/*
 * time.cpp
 *
 *  Created on: Jul 18, 2016
 *      Author: nsamson
 */

#include "time.hpp"
#include <string.h>
#include <string>

using namespace udg;
using namespace udg::err;

static bool init = false;
static sgx_time_source_nonce_t time_source_nonce;

static void initialize() {
	if (init) {
		return;
	}

	sgx_create_pse_session();

	uint64_t t;
	sgx_get_trusted_time(&t, &time_source_nonce);
	(void)t;

	sgx_close_pse_session();

	init = true;
}

uint64_t udg::get_time() {

	initialize();


	sgx_create_pse_session();
	uint64_t out;
	sgx_time_source_nonce_t new_nonce;
	sgx_get_trusted_time(&out, &new_nonce);
	sgx_close_pse_session();

	if (!std::equal(new_nonce, new_nonce + 32, time_source_nonce)) {
		throw time_nonce_changed(time_source_nonce, new_nonce);
	}

	return out;
}

udg::err::time_nonce_changed::time_nonce_changed(const sgx_time_source_nonce_t& old, const sgx_time_source_nonce_t& _new) : std::runtime_error(std::string("Time nonce changed! Did system time change?")) {
	memcpy(this->new_nonce, _new, sizeof(sgx_time_source_nonce_t));
	memcpy(this->old_nonce, old, sizeof(sgx_time_source_nonce_t));
};
