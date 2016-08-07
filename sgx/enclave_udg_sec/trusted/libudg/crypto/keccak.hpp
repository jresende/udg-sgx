//
// Created by nsamson on 7/12/16.
//

#ifndef UDG_SHA3PP_HPP
#define UDG_SHA3PP_HPP

#include "sha3.h"
#include "../ethereum/rlp.hpp"
#include "../byte_array.hpp"
#include <string>
#include <stdint.h>
#include <stdexcept>

namespace udg {
    namespace crypto {
        class keccak256 {
            sha3_context ctxt;
            bool finalized;

        public:
            keccak256();

            void update(const uint8_t* buf, size_t len);
            void update(const std::string& msg);

            template <unsigned long int N>
            void update(const FixedSizedByteArray<N>& bytes) {
            	this->update(bytes.data(), N);
            }

            void finalize();

            void get_digest(uint8_t* buf) const;
            h256 get_digest() const;

        };
        class keccak384 {
            sha3_context ctxt;
            bool finalized;

        public:
            keccak384();

            void update(const uint8_t* buf, size_t len);
            void update(const std::string& msg);

            template <unsigned long int N>
			void update(const FixedSizedByteArray<N>& bytes) {
				this->update(bytes.data(), N);
			}

            void finalize();

            void get_digest(uint8_t* buf) const;
            h384 get_digest() const;
        };
        class keccak512 {
            sha3_context ctxt;
            bool finalized;

        public:
            keccak512();

            void update(const uint8_t* buf, size_t len);
            void update(const std::string& msg);

            template <unsigned long int N>
			void update(const FixedSizedByteArray<N>& bytes) {
				this->update(bytes.data(), N);
			}

            void finalize();

            void get_digest(uint8_t* buf) const;
            h512 get_digest() const;
        };

        std::string digest_str(const keccak256&);
        std::string digest_str(const keccak384&);
        std::string digest_str(const keccak512&);

        h256 rlp_keccak256(const rlp::RLPConvertable&);

        class keccak_not_finalized : public std::runtime_error {
        public :
        	keccak_not_finalized() : std::runtime_error("Cannot get digest before finalizing hash.") {}
        };
    }
}

#endif //UDG_SHA3PP_HPP
