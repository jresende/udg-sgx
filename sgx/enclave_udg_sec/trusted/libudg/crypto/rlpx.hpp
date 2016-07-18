//
// Created by nsamson on 7/10/16.
//

#ifndef UDG_RLPX_HPP
#define UDG_RLPX_HPP

#include <stdint.h>
#include <vector>
#include "../sockets.hpp"
#include "rand.hpp"
#include "secp256k1/include/secp256k1.h"
#include <memory>
#include "ecc.hpp"

// Ethereum uses ECIES w/ AES128-CTR-SHA256
// SHA256 is the sgx sha256
//

namespace udg {

    namespace crypto {

    	void current_rlpx_version(h256& out);

    	struct Endpoint {
			uint32_t inet_addr;
			uint16_t udp_port;
			uint16_t tcp_port;
		};

    	struct PingNode {
    		h256 version;
    		Endpoint from;
    		Endpoint to;
    		uint32_t timestamp;
    	};

    	struct Pong {
			Endpoint to;
			h256 echo;
			uint32_t timestamp;
    	};

    	struct FindNeighbours {
			PublicKey target;
			uint32_t timestamp;
    	};

    	struct Neighbor {
    		Endpoint endpoint;
    		PublicKey node;
    	};

    	struct Neighbours {
			std::vector<Neighbor> nodes;
			uint32_t timestamp;
    	};

    	// For now, assume nodes are hardcoded.
//    	std::vector<Neighbor> discover_peers(uint32_t bootstrap_node, uint16_t port);

    	class RLPxSession {

    		KeyPair ephemeral_keys;
    		PublicKey dest;
    		SocketConnection conn;
    		h256 nonce;
    		Secret static_shared_secret;
    		Secret ephemeral_shared_secret;
    		h256 remote_nonce;

    		h256 shared_secret;
    		h256 aes_secret;
    		h256 mac_secret;

    		h256 ingress_mac;
    		h256 egress_mac;

    		std::vector<uint8_t> authInitiator;

    		void sendAuth();
    		void recvAck();

    	public:
    		RLPxSession(PublicKey node_id, uint32_t inet_addr, uint16_t port);

    		ssize_t send(const void* buf, size_t len);
    		ssize_t recv(void* buf, size_t len);

    	};

    	int load_or_gen_keys();

    	const KeyPair& get_keys();
    	void print_pub_key(); // Print this enclave's RLPx public key to console

    	std::vector<uint8_t> eciesKDF(const Secret& sec, const uint8_t addl_data[], size_t addl_data_len, unsigned out_len);

    	void encryptECIES(const PublicKey& pub, const uint8_t mac_data[], size_t mac_len, std::vector<uint8_t>& io);
    	int decryptECIES(const PrivateKey& priv, const uint8_t mac_data[], size_t mac_len, std::vector<uint8_t>& io);
    }
}

#endif //UDG_RLPX_HPP
