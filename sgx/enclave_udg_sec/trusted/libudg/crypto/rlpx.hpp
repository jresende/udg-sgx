//
// Created by nsamson on 7/10/16.
//

#ifndef UDG_RLPX_HPP
#define UDG_RLPX_HPP

#include <stdint.h>
#include <vector>
#include "../sockets.hpp"
#include "rand.hpp"

// Ethereum uses ECIES w/ AES128-CTR-SHA256
// SHA256 is the sgx sha256
//

namespace udg {

    namespace crypto {

    	typedef uint8_t RLPxPublicKey[64];
    	typedef uint8_t RLPxPrivateKey[32];
    	typedef uint8_t RLPxSecret[32];

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
			RLPxPublicKey target;
			uint32_t timestamp;
    	};

    	struct Neighbor {
    		Endpoint endpoint;
    		RLPxPublicKey node;
    	};

    	struct Neighbours {
			std::vector<Neighbor> nodes;
			uint32_t timestamp;
    	};

    	struct RLPxKeyPair {
    		RLPxPublicKey pub_key;
    		RLPxPrivateKey priv_key;

    		static RLPxKeyPair create_rand();

    		RLPxKeyPair();
    		RLPxKeyPair(const RLPxKeyPair& that);
    		RLPxKeyPair(const RLPxKeyPair&& that) = delete;

    		RLPxKeyPair& operator=(const RLPxKeyPair& that);

    		void dump_keys(uint8_t out[]) const;
    	};

    	// For now, assume nodes are hardcoded.
//    	std::vector<Neighbor> discover_peers(uint32_t bootstrap_node, uint16_t port);

    	class RLPxSession {

    		RLPxKeyPair ephemeral_keys;
    		SocketConnection conn;

    	public:
    		RLPxSession(RLPxPublicKey node_id, uint32_t inet_addr, uint16_t port);

    		ssize_t send(const void* buf, size_t len);
    		ssize_t recv(void* buf, size_t len);

    	};

    	int load_or_gen_keys();

    	const RLPxKeyPair& get_keys();
    	void print_pub_key(); // Print this enclave's RLPx public key to console

    	std::vector<uint8_t> eciesKDF(const RLPxSecret& sec, const uint8_t addl_data[], size_t addl_data_len, unsigned out_len);

    	void encryptECIES(const RLPxPublicKey& pub, const uint8_t mac_data[], size_t mac_len, std::vector<uint8_t>& io);
    	int decryptECIES(const RLPxPrivateKey& priv, const uint8_t mac_data[], size_t mac_len, std::vector<uint8_t>& io);
    }
}

#endif //UDG_RLPX_HPP
