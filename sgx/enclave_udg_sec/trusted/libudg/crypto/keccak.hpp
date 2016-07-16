//
// Created by nsamson on 7/12/16.
//

#ifndef UDG_SHA3PP_HPP
#define UDG_SHA3PP_HPP

#include "sha3.h"
#include <string>
#include <stdint.h>

namespace udg {
    namespace crypto {
        class keccak256 {
            sha3_context ctxt;

        public:
            keccak256();

            void update(const uint8_t* buf, size_t len);
            void update(const std::string& msg);

            void finalize();

            void get_digest(uint8_t* buf) const;

        };
        class keccak384 {
            sha3_context ctxt;

        public:
            keccak384();

            void update(const uint8_t* buf, size_t len);
            void update(const std::string& msg);

            void finalize();

            void get_digest(uint8_t* buf) const;
        };
        class keccak512 {
            sha3_context ctxt;

        public:
            keccak512();

            void update(const uint8_t* buf, size_t len);
            void update(const std::string& msg);

            void finalize();

            void get_digest(uint8_t* buf) const;
        };

        std::string digest_str(const keccak256&);
        std::string digest_str(const keccak384&);
        std::string digest_str(const keccak512&);
    }
}

#endif //UDG_SHA3PP_HPP
