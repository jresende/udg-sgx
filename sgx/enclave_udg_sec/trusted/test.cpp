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
#include "libudg/crypto/all_hash.hpp"
#include "libudg/hex_encode.hpp"
#include "libudg/io.hpp"
#include "libudg/crypto/secp256k1/include/secp256k1_recovery.h"
#include "libudg/crypto/secp256k1/include/secp256k1.h"
#include "libudg/ethereum/rlp.hpp"
#include "libudg/time.hpp"
#include "libudg/ethereum/blockchain.hpp"
#include "libudg/ethereum/ethash.hpp"
#include "libudg/BigInt.hpp"
#include <algorithm>
#include <stdint.h>
#include <sgx_tcrypto.h>

using namespace udg;
using namespace udg::crypto;
using namespace udg::rlp;

#define EQ_LINE "==================================="

int ecall_udg_test_rlp() {

//    io::cdebug << "Current time: " << get_time();

	io::cdebug << EQ_LINE;
	io::cdebug << __PRETTY_FUNCTION__
			<< EQ_LINE;

    std::vector<std::string> ss;
    ss.push_back("a");
    ss.push_back("abcdefghijklmnopqrstuvwxyz");
    ss.push_back("Yet another string. Hopefully, this is long enough to trigger something.");
    ss.push_back("Here's the last string.");

    std::vector<rlpvec> rs;

    for (auto& str : ss) {
        rs.push_back(to_rlp(str));
    }

    rlpvec ls = to_rlp_list(rs);

    RLPData r;
    r.parse_bytes(ls.begin(), ls.end());

    io::cdebug << "Decoded RLP: " << r.to_string();

    std::string sample_block =
        "f90216f90211a0143ac4afb4d18f8c57298595cccbf0a5605e3c7a2aa74aa59b53a35bc9a10144a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347949fc6fefd7f33ca29ee17f2bfec944695e5f29cafa071a9c94bece6eff063d5474582f6fd71ca5bda4638b22d6b89fa98d98202d19ba056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008303a3d38206c0832fefd88084563188e698d783010300844765746887676f312e352e31856c696e7578a03387bf1962d1a35557874c973ab362367986c952294c9bd705f2d5db5c8f74b58864a07c1afab14df0c0c0";

    std::string sample_block_with_transaction =
        "f9034df90216a0339ff88033f60ba77001d9f19bc47d4d0d7e46a3e29a89fed87ea51db39a7919a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794e1af37a03706c6aac599276f887091f2a3845b78a0e0c66c10fb1990ed4b24223bf88f5174cf846308a7ff74d617d7e116cd831143a0e43c75b52f4e678ef98380fb96a20d91f665f60b2bf84a375e4e50b4c632f693a08d5ca965e4181b2d89c8344ef64ec5dcae9af98563ea966d9bfe4c36c1511407b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000083456c0d83016df1832fefd88302d7f1845658d07299d883010400844765746887676f312e352e318664617277696ea0722673da13ba2159879141b53a1797eef4238ac6b0061e28a069eb297512159a882f71d691a9a3632cf90130f9012d83102dad850ba43b740083124f8094d34e752661c770ee2eb078326ed7a2a09acff13580b8c413f955e100000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000005003000000013e3a114c28d4167431c41d8a34a06d8095663a6348cd000000000000000000bf413a9b08407fbb93850da92fb69c1d959fd3a8c46210cb444f623a10f7ffa629cf5856761e0f18f9d3cad4000000000000000000000000000000001ca025db8900cbf3ce3d15c6bc7be4906a24f03bbd38ab78aa5a19aa5b305eae5148a02eb8f6c14a8291fcb8a85bb4dbb0fe887d6c93ae469bb378112513b62c0a9dfbc0";

    std::string sample_block_with_uncle =
        "f9042ff90213a063e2ef6afbfe51ae061ef3a1be5898c16dd932984509c9fda5c13741ff324e1da09b828a2b252cef7300bb999ddf6691b1f9f95bb6c34b0e92b94e5f80f586bb2f94e1af37a03706c6aac599276f887091f2a3845b78a0b5bb8f80ec4e419ac26b138242b5d82885106e082b1205616459c3541b76587fa056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008345d47183016dfd832fefd880845658d0a299d883010400844765746887676f312e352e318664617277696ea08cab21ec9c00af50af774319ef73ab58722928fbaf99cf6f140e2865e9c4293d8850a68c081a717856c0f90215f90212a0fd5c38da42b73e93d0cceb25cf6eeda588dff9439931cfa8b7bbf45e0d90db62a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794844e9d7790bcafd2a010b441c47c034f025231c4a05af3e816bf30c42cee77c2dbbbbd30e4b7b6572d0d686b5c212b96a86c65d138a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008345c30083016dfb832fefd880845658d09a98d783010400844765746887676f312e352e31856c696e7578a06e3989acc25fb48bb94935048215d96fe4d6d56a405f160fbcd8f99e3e88c40488168417b7c217dd05";
    r = RLPData();
    auto bin_dat = udg::hex_decode(sample_block_with_uncle);
    io::cdebug << udg::hex_encode(&bin_dat[0], bin_dat.size());

    r.parse_bytes(bin_dat.begin(), bin_dat.end());

    io::cdebug << r.to_hex_string();

    eth::Block simple(sample_block_with_uncle);
    rlpvec blk_rlp = simple.to_rlp();

    io::cdebug << "Simple sample block (no uncles or txns)"
        << udg::hex_encode(&blk_rlp[0], blk_rlp.size())
        << "Hash: "
        << simple.hash().to_string()
        << "From: "
        << simple.header.coinbase.to_string();

    io::cout << simple.header.to_string() << "\n";

    for (auto& tx : simple.transactions) {
        io::cout << tx.to_string() << "\n";
        io::cout << "Hash: " << tx.hash().to_string() << "\n";
        io::cout << "TXFrom: " << tx.from().to_string() << "\n";

        Signature sig = tx.sig();
        h256 sig_hash = tx.sig_hash();
        io::cdebug << (crypto::verify(crypto::recover(sig, sig_hash), sig, sig_hash) ? 0 : 1);
    }


    for (auto& unc : simple.uncles) {
        io::cdebug << "Block uncle follows:"
            << "Hash: "
            << crypto::rlp_keccak256(unc).to_string()
            << "From: "
            << unc.coinbase.to_string();

        io::cout << unc.to_string() << "\n";

    }

    io::cout << simple.to_string() << "\n";

    if (!simple.validate()) {
    	io::cdebug << "Failed to validate block";
    	return 1;
    }

    return 0;
}

int ecall_udg_test_ECIES() {

	io::cdebug << EQ_LINE;
	io::cdebug << __PRETTY_FUNCTION__
			<< EQ_LINE;

#ifndef NDEBUG
    udg::crypto::load_or_gen_keys();
    const KeyPair& kp1 = udg::crypto::get_keys();

    std::string kp1_pub = hex_encode(kp1.pub_key.data(), PublicKey::size);
    std::string kp1_priv = hex_encode(kp1.priv_key.data(), PrivateKey::size);

    KeyPair ephem = KeyPair::create_rand();

    printf("PubKey1:  %s\n", kp1_pub.c_str());
    printf("PrivKey1: %s\n", kp1_priv.c_str());

    Secret s1 = shared_secret(kp1.pub_key, ephem.priv_key);
    Secret s2 = shared_secret(ephem.pub_key, kp1.priv_key);

    io::cdebug << "Shared secret 1" << s1.to_string();
    io::cdebug << "Shared secret 2" << s2.to_string();
    if (s1 != s2) {
        io::cdebug << "SHARED SECRET NOT WORKING";
    }

    std::string h = "Hello, world!";

    printf("Encrypting: %s\n", h.c_str());

    std::vector<uint8_t> io(h.begin(), h.end());

    encryptECIES(kp1.pub_key, {}, 0, io);

    std::string encrypted_data = hex_encode(&io[0], io.size());

    printf("Return code for decrypt: %d\n", decryptECIES(kp1.priv_key, {}, 0, io));

    std::string decrypted_data(io.begin(), io.end());

    printf("Decrypted string is: %s\n", decrypted_data.c_str());

    std::string decrypted_data_hex = hex_encode(&io[0], io.size());
    printf("Encrypted string (hex): %s\n", encrypted_data.c_str());
    printf("Decrypted string (hex): %s\n", decrypted_data_hex.c_str());

    if (h.compare(decrypted_data) != 0) {
        return -1;
    }

    secp256k1_context* c = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    io::cdebug << "Verify key" << secp256k1_ec_seckey_verify(c, kp1.priv_key.data());

#endif

    return 0;
}

int ecall_udg_test_RLPxHandshake() {

//    io::cdebug << "Current time: " << get_time();
    io::cdebug << "RLPxHandshake Test";

    io::cdebug << EQ_LINE;
	io::cdebug << __PRETTY_FUNCTION__
			<< EQ_LINE;

#ifndef NDEBUG
    udg::crypto::load_or_gen_keys();

    "dc04cb84c0a8000282765f82765fc9844f84e88f82765f8084578dc604";

    io::cdebug << "Loaded keys...";

    std::string local_node = "5288104fef7a1c743ff80cdd775fc19b07b90ebee61067263b35dd4acf67fce28c69a2d98495b1c274e0b64f955a294fc8a804b4c75fc24d4655c1dfcc6a75f1";
    //  std::string local_node = "e76d49abcf53d9530759fcff3083176d4507fcd605d7128508389f43c35897a956f155f945c83b268a5dd7157edf5ea9496538e319144f7ba9d0cb3c81477f3c";
    auto local_node_bytes = hex_decode(local_node);
    PublicKey node_id(local_node_bytes.begin(), local_node_bytes.end());

    io::cdebug << "Node ID loaded.";

    std::string local_ip = "127.0.0.1";
    uint32_t ip_addr = ip_addr_str_to_int(local_ip);
    printf("%08X\n", ip_addr);

    uint16_t port = 30303;

    RLPxSession rlpx(node_id, ip_addr, port);

    io::cdebug << "Made it!";
#endif

    return 0;
}

int ecall_udg_test_uint256() {

	io::cdebug << EQ_LINE;
	io::cdebug << __PRETTY_FUNCTION__
			<< EQ_LINE;

//	uint256 bi = uint256(FixedSizedByteArray<32>(0xA5));
	uint256 bi("0xFFEEDDCCFFEEDDCC");
	uint256 bi2;
//	uint256 two("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
	uint256 two("0x2");
	uint256 four = 4;

//	uint256 two("0xFFFF");


	uint256 r = uint256::random() >> 128;

	io::cdebug << ((bi + bi2) == bi);

	io::cdebug << bi.to_string();
	io::cdebug << (bi << 120).to_string();
	io::cdebug << (bi << 120 >> 80).to_string();
	io::cdebug << ((bi << 120 >> 80) == (bi << 20 << 15 << 5));

	uint256 one = 1;

	io::cdebug << "LShift";
	for (unsigned i = 0; i < 255; i++) {
//		io::cdebug << one.to_string();
		one <<= 1;
	}
	io::cdebug << one.to_string();

	io::cdebug << "LShift done";

	io::cdebug << "RShift";
	for (unsigned i = 0; i < 255; i++) {
//			io::cdebug << one.to_string();
		one >>= 1;
	}
	io::cdebug << one.to_string();

	io::cdebug << "RShift done";

	io::cdebug << "Multiplication" << two.to_string();
	io::cdebug << ((two) * (two)).to_string();
	io::cdebug << "Rand";
	for (uint8_t i = 0; i < 255; i++) {
//		io::cdebug << "Round: " << (unsigned) i;
		r = uint256::random() >> 128;
//		io::cdebug << r.to_string();

		auto mul = r * r;
		auto div = mul / r;

//		io::cdebug << "Mult";
//		io::cdebug << mul.to_string();
//
//		io::cdebug << "Division";
//		io::cdebug << div.to_string();

		if (div != r) {
			return 1;
		}
	}





    return 0;
}

#define BARRAY_SIZE 64
int ecall_udg_test_byte_array() {


	io::cdebug << EQ_LINE;
	io::cdebug << __PRETTY_FUNCTION__
			<< EQ_LINE;

	FixedSizedByteArray<BARRAY_SIZE> zarr;
	auto rand = FixedSizedByteArray<BARRAY_SIZE>::random();

	io::cdebug << "===== BYTE ARRAY TESTS =====\n";

	io::cdebug << "Test array :"
			<< rand.to_string();

	io::cdebug << "XOR'd with self"
			<< (rand ^ rand).to_string();

	if ((rand ^ rand) != zarr) {
		io::cdebug << "XOR NOT WORKING";
		return 1;
	}

	rand ^= rand;

	if (rand != zarr) {
		io::cdebug << "^= NOT WORKING";
		return 1;
	}

	// 0xAA = 10101010
	// 0x55 = 01010101

	auto& aa = rand; // avoid massive stack via reuse
	std::fill(aa.begin(), aa.end(), 0xAA);

	FixedSizedByteArray<BARRAY_SIZE> x55(0x55);

	io::cdebug << "AA:"
			<< aa.to_string()
			<< "55:"
			<< x55.to_string();

	FixedSizedByteArray<BARRAY_SIZE> ff(0xFF);

	io::cdebug << "Operator tests"
			<< ((aa ^ x55) == ff)
			<< ((x55 ^ aa) == ff)
			<< ((x55 | aa) == ff)
			<< ((aa | x55) == ff)
			<< ((aa & x55) == zarr)
			<< ((x55 & aa) == zarr);


	rand = FixedSizedByteArray<BARRAY_SIZE>::random();

	io::cdebug << "Slices";
//	io::cdebug << "First section is making sure slices and ref slices work similarly."
//			<< "Second part acts like this:";
//	io::cdebug << "XOR'd byte reference slice: first is slice view,"
					"\nsecond is slice pre-op, third is the real backing array.";

	for (uint64_t i = 0; i < BARRAY_SIZE / 8; i++) {
		auto bar_a = rand.slice_ref<8>(i * 8);
		auto actual_slice = rand.slice<8>(i * 8);

		io::cdebug << i
				<< bar_a.to_string()
				<< actual_slice.to_string();

		if (!std::equal(bar_a.begin(), bar_a.end(), actual_slice.begin())) {
			return 1;
		}

		bar_a ^= bar_a;

		io::cdebug << "Part two.";

//		io::cdebug << bar_a.to_string();
//		io::cdebug << actual_slice.to_string();
//		io::cdebug << rand.slice<8>(i*8).to_string();

	}

	auto& a5 = rand;
	auto& x5a = x55;

	std::fill(a5.begin(), a5.end(), 0xA5);
	std::fill(x5a.begin(), x5a.end(), 0x5A);

	FixedSizedByteArray<4> test;
	test.slice_ref<4>(0) ^= FixedSizedByteArray<4>::from<uint32_t>(0xFFAAFFDD);

	io::cdebug << test.to_string();

	if (test.reinterpret<uint32_t>() != 0xFFAAFFDD) {
		return 1;
	}

	return 0;

}

int ecall_test_ethash() {

	io::cdebug << "========================="
	    	<< __PRETTY_FUNCTION__
	    	<< "=========================";

	{
		h256 dag_seed((const uint8_t*)"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~", 32);
		eth::EthashCache ec1(1024, dag_seed);
		io::cdebug << "0xb1698f829f90b35455804e5185d78f549fcb1bdce2bee006d4d7e68eb154b596be1427769eb1c3c3e93180c760af75f81d1023da6a0ffbe321c153a7c0103597";
		io::cdebug << ec1.calc_dataset_item(0).to_string();

		if (h512("b1698f829f90b35455804e5185d78f549fcb1bdce2bee006d4d7e68eb154b596be1427769eb1c3c3e93180c760af75f81d1023da6a0ffbe321c153a7c0103597")
				!= ec1.calc_dataset_item(0)) {
			return 1;
		}
	}

	h256 seed("372eca2454ead349c3df0ab5d00b0b706b23e49d469387db91811cee0358fc6d");

	eth::EthashCache ec = eth::ethash::get_cache(22);
	auto res = ec.hashimoto(eth::ethash::get_full_size(22),
			seed, FixedSizedByteArray<8>::from<uint64_t>(0x495732e0ed7a801c), false);

	io::cdebug << "Should be:"
			<< "0x00000b184f1fdd88bfd94c86c39e65db0c36144d5e43f745f722196e730cb614"
			<< res.result.to_string()
			<< res.mix_digest.to_string();

	if (res.result != h256("00000b184f1fdd88bfd94c86c39e65db0c36144d5e43f745f722196e730cb614")) {
		io::cdebug << "Not working!";
		return 1;
	} else {
		io::cdebug << "ETHASH IS FREAKIN' WORKING!";
	}

	return 0;
}

int ecall_test() {
	return
			ecall_udg_test_rlp()
			|| ecall_udg_test_ECIES()
			|| ecall_udg_test_uint256()
			|| ecall_udg_test_byte_array()
			|| ecall_test_ethash();
}
