#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "udg_sec.h"
#include "udg_sec_t.h"  /* print_string */
#include "libudg/ethereum/blockchain.hpp"
#include "libudg/ethereum/ethash.hpp"
#include "libudg/ethereum/trie.hpp"
#include "libudg/crypto/all_hash.hpp"
#include "libudg/crypto/ez_seal.hpp"
#include "libudg/hex_encode.hpp"
#include "libudg/invoke.hpp"
#include "libudg/io.hpp"
#include <stdexcept>

using namespace udg;

const eth::Address contract_addr("0x1ebe783bfa886145b18c849afeedce2f24bb196d");
const h256 genesis_hash("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3");

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

		io::cdebug << udg::hex_encode(blk.to_rlp());

		bool valid = blk.validate();

		io::cout << "Is Valid Block? " << valid << "\n";

		io::cout << "Signed Hash: ";

        if (valid) {
		    auto kp = udg::crypto::KeyPair::create_enclave_pair();
		    auto sig = udg::crypto::sign(kp.priv_key, blk.hash());
		    io::cout << sig.to_string();
        }

		io::cout << "\n";

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

int ecall_udg_process(const char* blk) {

	// ensure this block immediately follows previous block.

	try {
		eth::Block b(blk);

		auto h = b.hash();
		io::cdebug << "Block rlp" << udg::hex_encode(b.to_rlp());

//		rlp::rlpvec dat = udg::hex_decode(proof);
//		{
//			rlp::RLPData proof_list;
//			proof_list.parse_bytes(dat.begin(), dat.end());
//
//			rlp::rlpdlist elements;
//			proof_list.retrieve_arr(elements);
//
//			rlp::rlplist proof;
//			for (auto& proof_d : elements) {
//				rlp::rlpvec elem;
//				proof_d.retrieve_bytes(elem);
//				proof.push_back(elem);
//			}
//
////			if (!udg::eth::MemoryTrie::verify_proof(
////					b.header.root,
////					std::vector<uint8_t>(h.begin(), h.end()),
////					proof
////			)) {
////				io::cout << "Invalid proof for block.";
////				return -1;
////			}
//		}

		if (!b.validate()) {
			io::cout << "Block did not validate.";
			return -1;
		} else {
			eth::ethash::clear_cache();
		}

		auto fname = contract_addr.to_string();
		fname.append(".eth");
		try {
			io::file f(fname);

			FixedSizedByteArray<1024> buf;
			f.read(buf.data(), sgx_calc_sealed_data_size(0, h256::size));

			auto phash = udg::crypto::unseal_data(buf.data(), h256::size);
			h256 parent_hash(phash.begin(), phash.end());
			io::cdebug << "Read hash"
								<< parent_hash.to_string();

			if (b.header.parent_hash != parent_hash) {
				io::cout << "Block parent hash and stored previous block hash do not match!\n";
				io::cout << "Block parent hash: " << b.header.parent_hash.to_string() << "\n";
				io::cout << "Stored Parent: " << parent_hash.to_string() << "\n";
				return 1;
			}

		} catch (std::runtime_error& e) {
			if (b.header.parent_hash != genesis_hash) {
				io::cout << "No data file and parent hash is not genesis block!\n";
				return 1;
			}
		}

		for (auto& t : b.transactions) {
			if (t.recipient == contract_addr) {
				io::cout << "Transaction " << t.hash().to_string() << " modifies contract " << contract_addr.to_string() << "\n";
			}
		}

		io::file f(fname, "w+");
		io::cdebug << "Writing hash" << b.hash().to_string();
		auto d = udg::crypto::seal_data(b.hash().data(), h256::size);
		f.write(&d[0], d.size());

		return 0;
	} catch (std::runtime_error& e) {
		io::cout << e.what() << "\n";
		return -1;
	}

}

int ecall_udg_print_pubkey() {
	auto kp = udg::crypto::KeyPair::create_enclave_pair();
	io::cout << kp.pub_key.to_string() << "\n";
	return 0;
}

int ecall_udg_recover(const char* sig, const char* hash) {
	crypto::Signature s(sig);
	h256 h(hash);

	auto rec = udg::crypto::recover(s, h);

	io::cout << rec.to_string() << "\n";
	return 0;
}
