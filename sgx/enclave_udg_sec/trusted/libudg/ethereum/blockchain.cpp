/*
 * blockchain.cpp
 *
 *  Created on: Aug 3, 2016
 *      Author: nsamson
 */

#include "blockchain.hpp"
#include "../crypto/all_hash.hpp"
#include "../algorithms.hpp"
#include "ethash.hpp"
#include "../io.hpp"
#include "trie.hpp"
#include <algorithm>
#include <stdio.h>
#include <stdexcept>
#include <iterator>

using namespace udg;
using namespace udg::rlp;
using namespace udg::crypto;
using namespace udg::eth;

std::string udg::eth::Transaction::to_string() const {
	std::string out = "Transaction ";
	out.append(this->to_rlp_str());
	return out;
}

udg::eth::Transaction::Transaction(const std::vector<RLPData>& from_rlp) {

	if (from_rlp.size() != 9) {
		throw std::invalid_argument("Invalid transaction RLP.");
	}

	rlpvec acc_non;
	rlpvec price;
	rlpvec gas_limit;
	rlpvec to_addr;
	rlpvec amount;
	rlpvec payload;
	rlpvec v;
	rlpvec r,s;

	from_rlp[0].retrieve_bytes(acc_non);
	from_rlp[1].retrieve_bytes(price);
	from_rlp[2].retrieve_bytes(gas_limit);
	from_rlp[3].retrieve_bytes(to_addr);
	from_rlp[4].retrieve_bytes(amount);
	from_rlp[5].retrieve_bytes(payload);
	from_rlp[6].retrieve_bytes(v);
	from_rlp[7].retrieve_bytes(r);
	from_rlp[8].retrieve_bytes(s);

	this->account_nonce = FixedSizedByteArray<8>(&acc_non[0], acc_non.size(), true);
	this->price = uint256(price.begin(), price.end(), true);
	this->gas_limit = uint256(gas_limit.begin(), gas_limit.end(), true);
	this->recipient = Address(to_addr.begin(), to_addr.end());
	this->amount = uint256(amount.begin(), amount.begin(), true);
	this->payload = std::vector<uint8_t>(payload.begin(), payload.end());
	this->V = v[0];
	this->R = uint256(r.begin(), r.end(), true);
	this->S = uint256(s.begin(), s.end(), true);
}

Signature udg::eth::Transaction::sig() const {
	h256 R_be = this->R.be_serialize();
	h256 S_be = this->S.be_serialize();

	Signature out;
	std::copy(R_be.begin(), R_be.end(), out.begin());
	std::copy(S_be.begin(), S_be.end(), out.begin() + 32);
	out[64] = this->V - 27;
	return out;
}

Address udg::eth::Transaction::from() const {
	Signature trans_sig = this->sig();
	SignatureStruct ss(trans_sig);

//	if (!ss.isValid()) {
//		return Address();
//	}

	PublicKey key = ss.recover(this->sig_hash());

	keccak256 ctxt;
	ctxt.update(key.data(), PublicKey::size);
	ctxt.finalize();
	h256 h;
	ctxt.get_digest(h.data());

	Address out(h.begin() + 12, h.end());

	return out;
}

h256 udg::eth::Transaction::sig_hash() const {
	rlpvec acc_non = this->account_nonce.to_rlp();
	rlpvec price = this->price.be_serialize().to_rlp();
	rlpvec gas_limit = this->gas_limit.be_serialize().to_rlp();
	rlpvec recipient = this->recipient.to_rlp_with_zeroes();
	rlpvec amount = this->amount.be_serialize().to_rlp();
	rlpvec payload = rlp::to_rlp(this->payload);

	std::vector<rlpvec> lst;
	lst.push_back(acc_non);
	lst.push_back(price);
	lst.push_back(gas_limit);
	lst.push_back(recipient);
	lst.push_back(amount);
	lst.push_back(payload);

	rlpvec trans_rlp = rlp::to_rlp_list(lst);

	keccak256 ctxt;
	ctxt.update(&trans_rlp[0], trans_rlp.size());
	ctxt.finalize();
	h256 out;
	ctxt.get_digest(out.data());

	return out;
}

h256 udg::eth::Transaction::hash() const {
	return rlp_keccak256(*this);
}

uint64_t udg::eth::Transaction::size() const {
	return this->to_rlp().size();
}

rlpvec udg::eth::Transaction::to_rlp() const {
	rlpvec acc_non = this->account_nonce.to_rlp();
	rlpvec price = this->price.be_serialize().to_rlp();
	rlpvec gas_limit = this->gas_limit.be_serialize().to_rlp();
	rlpvec recipient = this->recipient.to_rlp_with_zeroes();
	rlpvec amount = this->amount.be_serialize().to_rlp();
	rlpvec payload = rlp::to_rlp(this->payload);
	rlpvec v = rlp::to_rlp((char) this->V);
	rlpvec r = this->R.be_serialize().to_rlp();
	rlpvec s = this->S.be_serialize().to_rlp();

	std::vector<rlpvec> lst;
	lst.push_back(acc_non);
	lst.push_back(price);
	lst.push_back(gas_limit);
	lst.push_back(recipient);
	lst.push_back(amount);
	lst.push_back(payload);
	lst.push_back(v);
	lst.push_back(r);
	lst.push_back(s);

	rlpvec trans_rlp = rlp::to_rlp_list(lst);
	return trans_rlp;
}

std::string udg::eth::Header::to_string() const {
	char buf[1024 * 10] = {};
	snprintf(buf, 1024 * 10 - 1,
			"Header {"
			"    Parent: %s\n"
			"    Uncle: %s\n"
			"    Coinbase: %s\n"
			"    Root: %s\n"
			"    TxHash: %s\n"
			"    Receipt: %s\n"
			"    Bloom: %s\n"
			"    Difficulty: %s\n"
			"    Number: %s\n"
			"    Gas Limit: %s\n"
			"    Gas Used: %s\n"
			"    Time: %s\n"
			"    Extra: %s\n"
			"    Mix Digest: %s\n"
			"    Nonce: %s\n"
			"}",
			this->parent_hash.to_string().c_str(),
			this->uncle_hash.to_string().c_str(),
			this->coinbase.to_string().c_str(),
			this->root.to_string().c_str(),
			this->tx_hash.to_string().c_str(),
			this->receipt_hash.to_string().c_str(),
			this->bloom.to_string().c_str(),
			this->difficulty.be_serialize().to_string().c_str(),
			this->number.be_serialize().to_string().c_str(),
			this->gas_limit.be_serialize().to_string().c_str(),
			this->gas_used.be_serialize().to_string().c_str(),
			this->time.be_serialize().to_string().c_str(),
			hex_encode(this->extra).c_str(),
			this->mix_digest.to_string().c_str(),
			this->nonce.to_string().c_str()
	);
	return std::string(buf);
}

udg::eth::Header::Header(const std::vector<rlp::RLPData>& from_rlp) {

	if (from_rlp.size() != 15) {
		throw std::invalid_argument("Invalid Header RLP.");
	}

	rlpvec parent_hash;
	rlpvec uncle_hash;
	rlpvec coinbase;
	rlpvec root;
	rlpvec txhash;
	rlpvec receipt_hash;
	rlpvec bloom;
	rlpvec difficulty;
	rlpvec number;
	rlpvec gas_limit;
	rlpvec gas_used;
	rlpvec time;
	rlpvec extra;
	rlpvec mix_digest;
	rlpvec nonce;

	from_rlp[0].retrieve_bytes(parent_hash);
	from_rlp[1].retrieve_bytes(uncle_hash);
	from_rlp[2].retrieve_bytes(coinbase);
	from_rlp[3].retrieve_bytes(root);
	from_rlp[4].retrieve_bytes(txhash);
	from_rlp[5].retrieve_bytes(receipt_hash);
	from_rlp[6].retrieve_bytes(bloom);
	from_rlp[7].retrieve_bytes(difficulty);
	from_rlp[8].retrieve_bytes(number);
	from_rlp[9].retrieve_bytes(gas_limit);
	from_rlp[10].retrieve_bytes(gas_used);
	from_rlp[11].retrieve_bytes(time);
	from_rlp[12].retrieve_bytes(extra);
	from_rlp[13].retrieve_bytes(mix_digest);
	from_rlp[14].retrieve_bytes(nonce);

	this->parent_hash = h256(parent_hash.begin(), parent_hash.end());
	this->uncle_hash = h256(uncle_hash.begin(), parent_hash.end());
	this->coinbase = Address(coinbase.begin(), coinbase.end());
	this->root = h256(root.begin(), root.end());
	this->tx_hash = h256(txhash.begin(), txhash.end());
	this->receipt_hash = h256(receipt_hash.begin(), receipt_hash.end());
	this->bloom = Bloom(bloom.begin(), bloom.end());
	this->difficulty = uint256(difficulty.begin(), difficulty.end(), true);
	this->number = uint256(number.begin(), number.end(), true);
	this->gas_limit = uint256(gas_limit.begin(), gas_limit.end(), true);
	this->gas_used = uint256(gas_used.begin(), gas_used.end(), true);
	this->time = uint256(time.begin(), time.end(), true);
	this->extra = std::vector<uint8_t>(extra.begin(), extra.end());
	this->mix_digest = h256(mix_digest.begin(), mix_digest.end());
	this->nonce = BlockNonce(nonce.begin(), nonce.end());
}

rlp::rlpvec udg::eth::Header::to_rlp() const {
	rlpvec parent_hash = this->parent_hash.to_rlp_with_zeroes();
	rlpvec uncle_hash = this->uncle_hash.to_rlp_with_zeroes();
	rlpvec coinbase = this->coinbase.to_rlp_with_zeroes();
	rlpvec root = this->root.to_rlp_with_zeroes();
	rlpvec txhash = this->tx_hash.to_rlp_with_zeroes();
	rlpvec receipt_hash = this->receipt_hash.to_rlp_with_zeroes();
	rlpvec bloom = this->bloom.to_rlp_with_zeroes();
	rlpvec difficulty = this->difficulty.be_serialize().to_rlp();
	rlpvec number = this->number.be_serialize().to_rlp();
	rlpvec gas_limit = this->gas_limit.be_serialize().to_rlp();
	rlpvec gas_used = this->gas_used.be_serialize().to_rlp();
	rlpvec time = this->time.be_serialize().to_rlp();
	rlpvec extra = rlp::to_rlp(this->extra);
	rlpvec mix_digest = this->mix_digest.to_rlp_with_zeroes();
	rlpvec nonce = this->nonce.to_rlp_with_zeroes();

	std::vector<rlpvec> lst;
	lst.push_back(parent_hash);
	lst.push_back(uncle_hash);
	lst.push_back(coinbase);
	lst.push_back(root);
	lst.push_back(txhash);
	lst.push_back(receipt_hash);
	lst.push_back(bloom);
	lst.push_back(difficulty);
	lst.push_back(number);
	lst.push_back(gas_limit);
	lst.push_back(gas_used);
	lst.push_back(time);
	lst.push_back(extra);
	lst.push_back(mix_digest);
	lst.push_back(nonce);

	return rlp::to_rlp_list(lst);
}

h256 udg::eth::Block::hash() const {
	return crypto::rlp_keccak256(this->header);
}

uint64_t udg::eth::Block::size() const {
	return this->to_rlp().size();
}

udg::eth::Block::Block(const std::string& hex_rlp) {
	auto bin = udg::hex_decode(hex_rlp);
	this->load_rlp(bin);
}

udg::eth::Block::Block(const uint8_t* rlp, size_t len) {
	rlp::rlpvec r(rlp, rlp + len);
	this->load_rlp(r);
}

rlp::rlpvec udg::eth::Block::to_rlp() const {
	rlpvec header_dat = this->header.to_rlp();

	rlpvec txn_lst;

	{
		std::vector<rlpvec> txns;
		for (auto& tx : this->transactions) {
			txns.push_back(tx.to_rlp());
		}

		txn_lst = rlp::to_rlp_list(txns);
	}

	rlpvec unc_lst;

	{
		std::vector<rlpvec> uncs;
		for (auto& unc : this->uncles) {
			uncs.push_back(unc.to_rlp());
		}

		unc_lst = rlp::to_rlp_list(uncs);
	}

	std::vector<rlpvec> dat;
	dat.push_back(header_dat);
	dat.push_back(txn_lst);
	dat.push_back(unc_lst);

	return rlp::to_rlp_list(dat);
}

void udg::eth::Block::load_rlp(const rlpvec& rlp) {
	RLPData dat;
	auto len = dat.parse_bytes(rlp.begin(), rlp.end());
	if (((unsigned long)len) != rlp.size()) {
		throw std::invalid_argument("Invalid Block RLP.");
	}

	std::vector<RLPData> all_data;
	dat.retrieve_arr(all_data);

	{
		std::vector<RLPData> header_dat;
		all_data[0].retrieve_arr(header_dat);
		this->header = Header(header_dat);
	}

	{
		std::vector<RLPData> transactions;
		all_data[1].retrieve_arr(transactions);

		for (auto& tx : transactions) {
			std::vector<RLPData> tx_data;
			tx.retrieve_arr(tx_data);

			auto new_tx = Transaction(tx_data);
			this->transactions.push_back(new_tx);
		}
	}

	{
		std::vector<RLPData> uncles;
		all_data[2].retrieve_arr(uncles);

		for (auto& unc : uncles) {
			std::vector<RLPData> unc_data;
			unc.retrieve_arr(unc_data);

			auto new_head = Header(unc_data);
			this->uncles.push_back(new_head);
		}
	}

}

// Need to figure out why signature verification does not work
bool udg::eth::Transaction::validate() const {
	return true;
}

bool udg::eth::Header::validate() const {
	if (this->number != uint256::ZERO &&
			this->extra.size() > 32) {
		return false;
	}

	uint64_t blk_num = this->number.to_uint64_t();

	if (this->gas_limit < this->gas_used) {
		return false;
	}

	// Need to validate PoW
	EthashCache ecache = ethash::get_cache(blk_num);
	EthashResult res = ecache.hashimoto(ethash::get_full_size(blk_num),
			this->hash_no_nonce(),
			this->nonce,
			true);

	io::cdebug << "Ethash Result:" << res.result.to_string();
	if (res.mix_digest != this->mix_digest) {
		io::cout << "Invalid proof of work.\nGiven mix_digest:\n"
				<< this->mix_digest.to_string() << "\n"
				<< "Proper mix_digest:\n"
				<< res.mix_digest.to_string() << "\n"
				<< "Result: "
				<< res.result.to_string() << "\n";
		return false;
	}


	// Validate difficulty

	uint256 target = (uint256) (uint320::pow(2, 256) / ((uint320)this->difficulty));
	io::cdebug << "Target: " << target.to_string();
	uint256 result(res.result.begin(), res.result.end(), true);
	if (result > target) {
		io::cout << "Invalid hash result!\n"
				<< "Expected: " << target.to_string() << "\n"
				<< "Actual  : " << result.to_string() << "\n";
		return false;
	}




	return true;
}

h256 udg::eth::Header::hash_no_nonce() const {
	rlpvec parent_hash = this->parent_hash.to_rlp_with_zeroes();
	rlpvec uncle_hash = this->uncle_hash.to_rlp_with_zeroes();
	rlpvec coinbase = this->coinbase.to_rlp_with_zeroes();
	rlpvec root = this->root.to_rlp_with_zeroes();
	rlpvec txhash = this->tx_hash.to_rlp_with_zeroes();
	rlpvec receipt_hash = this->receipt_hash.to_rlp_with_zeroes();
	rlpvec bloom = this->bloom.to_rlp_with_zeroes();
	rlpvec difficulty = this->difficulty.be_serialize().to_rlp();
	rlpvec number = this->number.be_serialize().to_rlp();
	rlpvec gas_limit = this->gas_limit.be_serialize().to_rlp();
	rlpvec gas_used = this->gas_used.be_serialize().to_rlp();
	rlpvec time = this->time.be_serialize().to_rlp();
	rlpvec extra = rlp::to_rlp(this->extra);

	std::vector<rlpvec> lst;
	lst.push_back(parent_hash);
	lst.push_back(uncle_hash);
	lst.push_back(coinbase);
	lst.push_back(root);
	lst.push_back(txhash);
	lst.push_back(receipt_hash);
	lst.push_back(bloom);
	lst.push_back(difficulty);
	lst.push_back(number);
	lst.push_back(gas_limit);
	lst.push_back(gas_used);
	lst.push_back(time);
	lst.push_back(extra);

	auto x = rlp::to_rlp_list(lst);
	keccak256 ctxt;
	ctxt.update(&x[0], x.size());
	ctxt.finalize();
	return ctxt.get_digest();
}

bool udg::eth::Block::validate() const {

	bool head_ok = this->header.validate();
	bool tx_ok = udg::all_match(
			this->transactions.begin(),
			this->transactions.end(),
			[](const Transaction& x) -> bool {return x.validate();});
	bool unc_ok = udg::all_match(
			this->uncles.begin(),
			this->uncles.end(),
			[](const Header& x) -> bool {return x.validate();}
	);
	bool components_ok = head_ok && tx_ok && unc_ok;

	if (!components_ok) {
		io::cout << "Portion of block data failed consistency check.\n";

		if (!head_ok) {
			io::cout << "Header validation failed.\n";
		}

		if (!tx_ok) {
			io::cout << "Transaction validation failed.\n";
		}

		if (!unc_ok) {
			io::cout << "Uncle validation failed.\n";
		}

		return false;
	}

	// Validate hashes.

	//Tx Hash TODO: not actually working. Fix this next. Needs the TRIEHASH, not regular has
	//	{
	//
	//
	//		std::vector<rlpvec> txns;
	//		std::transform(this->transactions.begin(),
	//				this->transactions.end(),
	//				std::back_insert_iterator<std::vector<rlpvec> >(txns),
	//				[](const Transaction& x) -> rlpvec {return x.to_rlp();});
	//
	//        eth::MemoryTrie trie;
	//
	//        for (size_t i = 0; i < txns.size(); i++) {
	//            rlpvec txn_num_rlp = uint256(i).to_rlp();
	//            trie.update(txn_num_rlp, txns[i]);
	//        }
	//
	//        auto txns_sha = trie.hash();
	//
	//		if (txns_sha != this->header.tx_hash) {
	//			io::cout << "Transaction hash != Header Transaction hash\n";
	//			io::cout << txns_sha.to_string() << "\n";
	//			io::cout << this->header.tx_hash.to_string() << "\n";
	//			return false;
	//		}
	//	}

	{
		std::vector<rlpvec> uncs;
		std::transform(this->uncles.begin(),
				this->uncles.end(),
				std::back_insert_iterator<std::vector<rlpvec> >(uncs),
				[](const Header& x) -> rlpvec {return x.to_rlp();});

		rlpvec uncs_rlp = rlp::to_rlp_list(uncs);
		h256 uncs_sha;

		keccak256 ctxt;
		ctxt.update(&uncs_rlp[0], uncs_rlp.size());
		ctxt.finalize();
		uncs_sha = ctxt.get_digest();

		if (uncs_sha != this->header.uncle_hash) {
			io::cout << "Uncle hash != Header Uncle hash\n";
			io::cout << uncs_sha.to_string() << "\n";
			io::cout << this->header.uncle_hash.to_string() << "\n";
			return false;
		}
	}



	return true;
}

std::string udg::eth::Block::to_string() const {
	std::string out = "Block {\n";
	out.append(this->header.to_string());
	out.append("\n\n");
	out.append("Transactions{\n");

	for (auto& tx : this->transactions) {
		out.append(tx.to_string());
		out.append("\n");
	}

	out.append("}\n\nUncles {\n");

	for (auto& unc : this->uncles) {
		out.append(unc.to_string());
		out.append("\n");
	}

	out.append("}\n}");

	return out;
}
