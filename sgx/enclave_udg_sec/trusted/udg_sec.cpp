#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "udg_sec.h"
#include "udg_sec_t.h"  /* print_string */
#include "libudg/ethereum/blockchain.hpp"
#include "libudg/ethereum/ethash.hpp"
#include "libudg/ethereum/trie.hpp"
#include "libudg/crypto/all_hash.hpp"
#include "libudg/hex_encode.hpp"
#include "libudg/invoke.hpp"
#include "libudg/io.hpp"
#include <stdexcept>

using namespace udg;

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print(buf);
}

int ecall_udg_sec_main()
{
  printf("IN UDG_SEC\n");
  return 0;
}

int ecall_udg_parse(const char* rlp) {
	try {
		auto bin_dat = udg::hex_decode(rlp);
		eth::Block blk(&bin_dat[0], bin_dat.size());
		io::cout << blk.to_string()
				<< "\nBlock Hash:"
				<< blk.hash().to_string() << "\n";
	} catch (std::runtime_error& e) {
		io::cout << e.what() << "\n";
	}

	return 0;
}

int ecall_udg_verify(const char* rlp) {
	try {
		auto bin_dat = udg::hex_decode(rlp);
		eth::Block blk(&bin_dat[0], bin_dat.size());
		io::cout << blk.to_string()
				<< "\nBlock Hash:"
				<< blk.hash().to_string() << "\n";

		bool valid = blk.validate();

		io::cout << "Is Valid Block? " << valid << "\n";

		return valid ? 0 : 1;

	} catch (std::runtime_error& e) {
		io::cout << e.what() << "\n";
	}

	return -1;
}

int ecall_udg_generate_epoch(int epoch) {
	try {
		eth::EthashCache c(epoch);
		io::cout << "Generated epoch " << epoch << ", hash " << c.hash().to_string() << "\n";
		c.dump_to_file(epoch);

		return 0;
	} catch (std::runtime_error& e) {
		io::cout << e.what() << "\n";
		return -1;
	}
}

int ecall_udg_read_epoch(int epoch) {
	try {
		eth::EthashCache c(epoch);
		io::cout << "epoch " << epoch << ", hash " << c.hash().to_string() << "\n";

		return 0;
	} catch (std::runtime_error& e) {
		io::cout << e.what() << "\n";
		return -1;
	}
}

int ecall_udg_size_epoch(int epoch) {
	try {
		io::cout << udg::eth::ethash::get_cache_size(epoch * 30000) << "\n";
		return 0;
	} catch (std::runtime_error& e) {
		io::cout << e.what() << "\n";
		return -1;
	}
}

int ecall_udg_process(const char* blk, const char* proof, const char* transaction_hash) {
	try {
		eth::Block b(blk);

		auto h = b.hash();

		rlp::rlpvec dat = udg::hex_decode(proof);
		{
			rlp::RLPData proof_list;
			proof_list.parse_bytes(dat.begin(), dat.end());

			rlp::rlpdlist elements;
			proof_list.retrieve_arr(elements);

			rlp::rlplist proof;
			for (auto& proof_d : elements) {
				rlp::rlpvec elem;
				proof_d.retrieve_bytes(elem);
				proof.push_back(elem);
			}

//			if (!udg::eth::MemoryTrie::verify_proof(
//					b.header.root,
//					std::vector<uint8_t>(h.begin(), h.end()),
//					proof
//			)) {
//				io::cout << "Invalid proof for block.";
//				return -1;
//			}
		}

		if (!b.validate()) {
			io::cout << "Block did not validate.";
			return -1;
		} else {
			eth::ethash::clear_cache();
		}

		// Process transaction
//		auto res = udg::invoke::process_transactions(b.transactions);

//		 Add signature, then print.
//		crypto::keccak256 ctxt;
//		ctxt.update(&res[0], res.size());
//		ctxt.finalize();
//		h256 hash = ctxt.get_digest();

		bool verified_transaction = false;
		auto t_hash = h256(transaction_hash);

		for (auto& t : b.transactions) {
			io::cdebug << "Transaction hash";
			io::cdebug << t.hash().to_string();
			io::cdebug << t.sig_hash().to_string();
			if (t.hash() == t_hash) {
				auto kp = udg::crypto::KeyPair::create_enclave_pair();
				auto sig = udg::crypto::sign(kp.priv_key, t_hash);
				io::cout << sig.to_string() << "\n";
				return 0;
			}
		}

		return 0;
	} catch (std::runtime_error& e) {
		io::cout << e.what() << "\n";
		return -1;
	}

}
