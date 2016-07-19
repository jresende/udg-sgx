#include "rlpx.hpp"
#include "all_hash.hpp"
#include "ecc.hpp"
#include "../intconv.hpp"
#include "../time.hpp"
#include "../sockets.hpp"

using namespace udg;
using namespace udg::crypto;
using namespace udg::rlp;

//You have to discover a node before it will allow you to connect to it, it seems.
static std::vector<uint8_t> reversed_bytes(uint32_t num) {
	uint32_t swapped = byte_swap<uint32_t>(num);
	uint8_t* swap_ptr = reinterpret_cast<uint8_t*>(&num);
	return std::vector<uint8_t>(swap_ptr, swap_ptr + 4);
}

static std::vector<uint8_t> reversed_bytes(uint16_t num) {
	uint32_t swapped = byte_swap<uint16_t>(num);
	uint8_t* swap_ptr = reinterpret_cast<uint8_t*>(&num);
	return std::vector<uint8_t>(swap_ptr, swap_ptr + 2);
}

// Performs the encapsulation common to all packets
std::vector<uint8_t> common_encaps(const std::vector<uint8_t>& in) {
	std::vector<uint8_t> out;
	// Sign data
	const KeyPair& enclave_keys = get_keys();

	keccak256 k256;
	k256.update(&in[0], in.size());
	k256.finalize();

	h256 sha3_type_data;
	k256.get_digest(sha3_type_data.data());

	Signature s = sign(enclave_keys.priv_key, sha3_type_data);

	k256 = keccak256();
	k256.update(s.data(), Signature::size);
	k256.update(&in[0], in.size());
	k256.finalize();

	h256 hash;
	k256.get_digest(hash.data());

	out.insert(out.end(), hash.begin(), hash.end());
	out.insert(out.end(), s.begin(), s.end());
	out.insert(out.end(), in.begin(), in.end());

	return out;
}

Endpoint from_rlp_list(const std::vector<RLPData>& members) {
	rlpvec p;
	members[0].retrieve_bytes(p);

	Endpoint out;

	out.inet_addr = *reinterpret_cast<uint32_t*>(&p[0]);

	p.clear();
	members[1].retrieve_bytes(p);

	out.udp_port = *reinterpret_cast<uint16_t*>(&p[0]);

	p.clear();
	members[2].retrieve_bytes(p);

	out.tcp_port = *reinterpret_cast<uint16_t*>(&p[0]);

	return out;
}

Endpoint udg::crypto::Endpoint::from_rlp(const rlp::rlpvec& rlp) {
	RLPData data;
	data.parse_bytes(rlp.begin(), rlp.end());

	std::vector<RLPData> members;
	data.retrieve_arr(members);

	rlpvec p;
	members[0].retrieve_bytes(p);

	Endpoint out;

	out.inet_addr = FixedSizedByteArray<4>(p.begin(), p.end());

	p.clear();
	members[1].retrieve_bytes(p);

	out.udp_port = *reinterpret_cast<uint16_t*>(&p[0]);

	p.clear();
	members[2].retrieve_bytes(p);

	out.tcp_port = *reinterpret_cast<uint16_t*>(&p[0]);

	return out;
}

std::vector<uint8_t> udg::crypto::Endpoint::bytes() const {
	rlplist lst;
	{
		rlpvec addr = to_rlp(this->inet_addr.begin(), this->inet_addr.end());

		const uint8_t* swp = reinterpret_cast<const uint8_t*>(&this->udp_port);
		rlpvec udp_port = to_rlp(swp, swp + 2);

		swp = reinterpret_cast<const uint8_t*>(this->tcp_port);
		rlpvec tcp_port = to_rlp(swp, swp + 2);

		lst.push_back(addr);
		lst.push_back(udp_port);
		lst.push_back(tcp_port);
	}

	rlpvec out = to_rlp_list(lst);
	return out;
}

void udg::crypto::current_rlpx_version(h256& out) {
	out[h256::size - 1] = 3;
}

PingNode udg::crypto::PingNode::from_rlp(const rlp::rlpvec& rlp) {
	PingNode out;

	RLPData data;
	data.parse_bytes(rlp.begin(), rlp.end());

	std::vector<RLPData> rlpdata;
	rlpvec vers_dat;
	data.retrieve_arr(rlpdata);

	rlpdata[0].retrieve_bytes(vers_dat);

	out.version = h256(vers_dat.begin(), vers_dat.end());

	std::vector<RLPData> end_list;
	rlpdata[1].retrieve_arr(end_list);

	out.from = from_rlp_list(end_list);

	end_list.clear();
	rlpdata[2].retrieve_arr(end_list);

	out.to = from_rlp_list(end_list);

	rlpvec time_stamp;
	rlpdata[3].retrieve_bytes(time_stamp);

	uint32_t ts_swap = *reinterpret_cast<uint32_t*>(&time_stamp[0]);
	out.timestamp = byte_swap<uint32_t>(ts_swap);

	return out;
}

udg::crypto::PingNode::PingNode(const Endpoint& to, uint16_t port) {
	this->timestamp = get_time();
	this->from = get_me(port);
	this->to = to;
}

udg::crypto::PingNode::PingNode() : timestamp(0) {}

std::vector<uint8_t> udg::crypto::PingNode::encapsulate_packet() const {
	rlpvec vers = to_rlp(this->version.begin(), this->version.end());
	rlpvec from = this->from.bytes();
	rlpvec to = this->to.bytes();
	uint32_t be_time = byte_swap<uint32_t>(this->timestamp);
	uint8_t* be_time_ptr = reinterpret_cast<uint8_t*>(&be_time);
	rlpvec time = to_rlp(be_time_ptr, be_time_ptr + 4);

	std::vector<rlpvec> dlist;
	dlist.push_back(vers);
	dlist.push_back(from);
	dlist.push_back(to);
	dlist.push_back(time);

	rlpvec dat = to_rlp_list(dlist);
	dat.insert(dat.begin(), static_cast<uint8_t>(PacketType::PING_NODE));

	std::vector<uint8_t> out = common_encaps(dat);
	return out;
}

udg::crypto::Pong::Pong() : timestamp(0) {}

udg::crypto::Pong::Pong(const Endpoint& to) {
	this->timestamp = get_time();
	this->to = to;
}

Pong udg::crypto::Pong::from_rlp(const rlp::rlpvec& rlp) {
	Pong out;

	RLPData data;
	data.parse_bytes(rlp.begin(), rlp.end());

	std::vector<RLPData> rlpdata;
	rlpvec vers_dat;
	data.retrieve_arr(rlpdata);

	std::vector<RLPData> end_list;
	rlpdata[0].retrieve_arr(end_list);

	out.to = from_rlp_list(end_list);

	rlpvec time_stamp;
	rlpdata[1].retrieve_bytes(time_stamp);

	uint32_t ts_swap = *reinterpret_cast<uint32_t*>(&time_stamp[0]);
	out.timestamp = byte_swap<uint32_t>(ts_swap);

	return out;
}

std::vector<uint8_t> udg::crypto::Pong::encapsulate_packet() const {
	rlpvec to_vec = to.bytes();
	uint32_t be_time = byte_swap<uint32_t>(this->timestamp);
	uint8_t* be_time_ptr = reinterpret_cast<uint8_t*>(&be_time);
	rlpvec time = to_rlp(be_time_ptr, be_time_ptr + 4);

	std::vector<uint8_t> out;

	std::vector<rlpvec> rlpl;
	rlpl.push_back(to_vec);
	rlpl.push_back(time);

	rlpvec dat = to_rlp_list(rlpl);
	dat.insert(dat.begin(), static_cast<uint8_t>(PacketType::PONG));
	out = common_encaps(dat);
	return out;
}

FindNeighbours udg::crypto::FindNeighbours::from_rlp(const rlp::rlpvec& rlp) {
	FindNeighbours out;

	RLPData data;
	data.parse_bytes(rlp.begin(), rlp.end());

	std::vector<RLPData> lst;
	data.retrieve_arr(lst);

	rlpvec pubkey;
	lst[0].retrieve_bytes(pubkey);

	out.target = PublicKey(pubkey.begin(), pubkey.end());

	rlpvec time_stamp;
	lst[1].retrieve_bytes(time_stamp);

	uint32_t ts_swap = *reinterpret_cast<uint32_t*>(&time_stamp[0]);
	out.timestamp = byte_swap<uint32_t>(ts_swap);

	return out;
}

udg::crypto::FindNeighbours::FindNeighbours() : timestamp(0) {}
udg::crypto::FindNeighbours::FindNeighbours(const PublicKey& in) : timestamp(get_time()), target(in) {}

std::vector<uint8_t> udg::crypto::FindNeighbours::encapsulate_packet() const {
	rlpvec pub_key = to_rlp(this->target.begin(), this->target.end());

	uint32_t be_time = byte_swap<uint32_t>(this->timestamp);
	uint8_t* be_time_ptr = reinterpret_cast<uint8_t*>(&be_time);
	rlpvec time = to_rlp(be_time_ptr, be_time_ptr + 4);

	std::vector<rlpvec> rlpl;
	rlpl.push_back(pub_key);
	rlpl.push_back(time);

	rlpvec lst = to_rlp_list(rlpl);
	lst.insert(lst.begin(), static_cast<uint8_t>(PacketType::FIND_NEIGHBORS));

	std::vector<uint8_t> out = common_encaps(lst);
	return out;
}

Neighbor udg::crypto::Neighbor::from_rlp(const std::vector<RLPData>& members) {
	Neighbor out;

	rlpvec end_dat;
	members[0].retrieve_bytes(end_dat);

	rlpvec p;
	members[0].retrieve_bytes(p);

	out.endpoint.inet_addr = FixedSizedByteArray<4>(p.begin(), p.end());

	p.clear();
	members[1].retrieve_bytes(p);

	out.endpoint.udp_port = *reinterpret_cast<uint16_t*>(&p[0]);

	p.clear();
	members[2].retrieve_bytes(p);

	out.endpoint.tcp_port = *reinterpret_cast<uint16_t*>(&p[0]);

	p.clear();
	members[3].retrieve_bytes(p);

	out.node = PublicKey(p.begin(), p.end());

	return out;

}

std::vector<uint8_t> udg::crypto::Neighbor::encapsulate_packet() const {
	rlpvec addr = to_rlp(this->endpoint.inet_addr.begin(), this->endpoint.inet_addr.end());
	const uint8_t* swp = reinterpret_cast<const uint8_t*>(&this->endpoint.udp_port);
	rlpvec udp_port = to_rlp(swp, swp + 2);

	swp = reinterpret_cast<const uint8_t*>(this->endpoint.tcp_port);
	rlpvec tcp_port = to_rlp(swp, swp + 2);

	rlpvec node_id = to_rlp(this->node.begin(), this->node.end());

	std::vector<rlpvec> rlpl;
	rlpl.push_back(addr);
	rlpl.push_back(udp_port);
	rlpl.push_back(tcp_port);
	rlpl.push_back(node_id);

	return to_rlp_list(rlpl);
}

Neighbours udg::crypto::Neighbours::from_rlp(const rlp::rlpvec& rlp) {
	RLPData data;
	data.parse_bytes(rlp.begin(), rlp.end());

	std::vector<RLPData> all_data;
	data.retrieve_arr(all_data);

	std::vector<RLPData> neighbor_l;
//	all_data[0].retrieve_arr()


}

std::vector<uint8_t> udg::crypto::Neighbours::encapsulate_packet() const {
}

Endpoint udg::crypto::get_me(uint16_t port) {
	Endpoint out;

	uint32_t ip = get_ip();
	uint8_t* ip_ptr = reinterpret_cast<uint8_t*>(&ip);
	out.inet_addr = FixedSizedByteArray<4>(ip_ptr, ip_ptr + 4);
	out.udp_port = port;
	out.tcp_port = port;

	return out;
}
