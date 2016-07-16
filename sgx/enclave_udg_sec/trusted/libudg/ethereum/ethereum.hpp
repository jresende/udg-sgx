//
// Created by nsamson on 7/5/16.
//

#ifndef UDG_ETHEREUM_HPP
#define UDG_ETHEREUM_HPP

#include <string>
#include <vector>
#include <stdint.h>
#include "../invoke.hpp"

namespace udg {
    namespace ethereum {

        // based on "invoke(bytes)"
        const std::string INVOKE_SHA3_256 = "\x2f\xf6\x84\xe4";

        // based on "recordResult(bytes)"
        const std::string RECORD_RESULT_SHA3_256 = "\x32\x68\xec\x9e";

        std::string encode_bytes(const std::string& buf);
        std::string decode_bytes(const std::string& buf);
        std::string decode_bytes(const std::vector<uint8_t>& buf);
        std::string decode_bytes(const char* buf);

        std::string encode_invocation_results(const InvocationResult& res);
        int decode_invocation_results(InvocationResult& out, const std::string& buf);

        int decode_invocation_request(NativeInvocation& out, const std::string& buf);
        std::string encode_invocation_request(const NativeInvocation& in);
    }
}
#endif //UDG_ETHEREUM_HPP
