//
// Created by nsamson on 7/5/16.
//

#include "ethereum.hpp"

using namespace udg::ethereum;
using namespace udg;

std::string udg::ethereum::encode_bytes(const std::string &buf) {

    uint64_t str_size = buf.size();

    std::string out;
    out.append(32-8, '\0');

    uint64_t bswapped_size = udg::byte_swap(str_size);

    char* bswapped_size_ptr = reinterpret_cast<char*>(&bswapped_size);

    for (uint_fast8_t i = 0; i < 8; i++) {
        out.append(1, bswapped_size_ptr[i]);
    }

    out.append(buf);

    uint64_t padding_needed = out.size() % 32;

    out.append(32 - padding_needed, '\0');

    return out;

}

std::string udg::ethereum::decode_bytes(const char *buf) {
    uint256 str_size(buf, buf + 32);
    uint64_t smaller_str_size = str_size.to_uint64_t();

    return std::string(buf + 32, buf + 32 + smaller_str_size);
}

std::string udg::ethereum::decode_bytes(const std::vector<uint8_t> &buf) {
    return decode_bytes((const char *) &buf[0]);
}

std::string udg::ethereum::decode_bytes(const std::string &buf) {
    return decode_bytes(buf.c_str());
}

std::string udg::ethereum::encode_invocation_results(const InvocationResult &res) {
    std::string encoded_res = encode_bytes(res.to_string());
    std::string full_data = std::string(udg::ethereum::RECORD_RESULT_SHA3_256);
    full_data.append(encoded_res);

    return full_data;
}

int udg::ethereum::decode_invocation_request(NativeInvocation& out, const std::string &buf) {
    if (!buf.find(udg::ethereum::INVOKE_SHA3_256) == 0) {
        return -100;
    }

    std::string data_str = udg::ethereum::decode_bytes(buf.c_str() + 4);
    return out.parse_arg_str(data_str);
}

int ::udg::ethereum::decode_invocation_results(InvocationResult &out, const std::string &buf) {
    if (!buf.find(udg::ethereum::RECORD_RESULT_SHA3_256) == 0) {
        return -100;
    }

    std::string data_str = udg::ethereum::decode_bytes(buf.c_str() + 4);
    return out.parse_arg_str(data_str);
}

std::string udg::ethereum::encode_invocation_request(const NativeInvocation &in) {
    std::string unparsed_req = in.to_string();
    std::string encoded_req = udg::ethereum::encode_bytes(unparsed_req);

    return std::string(udg::ethereum::INVOKE_SHA3_256).append(encoded_req);
}











