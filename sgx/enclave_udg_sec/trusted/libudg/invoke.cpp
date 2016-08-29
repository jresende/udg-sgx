/*
 * invoke.cpp
 *
 *  Created on: Aug 29, 2016
 *      Author: nsamson
 */

#include "invoke.hpp"
#include "io.hpp"
#include <stdexcept>
#include <sgx_tseal.h>
#include "BigInt.hpp"
#include "crypto/all_hash.hpp"

using namespace udg;
using namespace udg::eth;
using namespace udg::crypto;
using namespace udg::rlp;

Address approved("7424aeb5c8e2b862b0b1cf7087fb75a13f72ebfc");
Address contract("");

rlp::rlpvec process_data(std::vector<uint8_t> transaction_data) {
	// We don't actually care about the data, since we're just incrementing a number.

	uint256 counter;
	uint32_t data_size = sgx_calc_sealed_data_size(0, h256::size);

	try {
		uint32_t l = 0;
		uint32_t tru_len = h256::size;
		io::file f("counter.dat", "r");

		h1024 buf;
		f.read(buf.data(), data_size);

		h256 cleartext;
		sgx_unseal_data(
				(sgx_sealed_data_t*) buf.data(),
				nullptr,
				&l,
				cleartext.data(),
				&tru_len
		);

		counter = uint256(cleartext.begin(), cleartext.end(), true);


	} catch (std::runtime_error& e) {
		// Need to generate file.
		counter = uint256(0ULL);
	}

	io::file f("counter.dat", "w+");
	counter += uint256::ONE;

	h256 cleartext = counter.be_serialize();

	h1024 buffer;

	sgx_seal_data(
			0,
			nullptr,
			(uint32_t)h256::size,
			cleartext.data(),
			data_size,
			(sgx_sealed_data_t*)buffer.data()
	);

	f.write(buffer.data(), data_size);

	return rlp::to_rlp((const char *)counter.to_hash().data(), h256::size);
}

rlp::rlpvec udg::invoke::process_transactions(
        const std::vector<eth::Transaction>& transactions) {

	for (auto& t : transactions) {
		auto sig = t.sig();
		auto h = t.sig_hash();
		auto pub_key = recover(sig, h);
		h256 key_hash;
		keccak256 ctxt;
		ctxt.update(pub_key);
		ctxt.finalize();
		key_hash = ctxt.get_digest();

		Address t_addr(key_hash.begin() + 12, key_hash.end());

		if (t_addr == approved) {
			return process_data(t.payload);
		}
	}

	return rlp::rlpvec();
}
