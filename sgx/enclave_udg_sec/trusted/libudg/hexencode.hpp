//
// Created by nsamson on 7/5/16.
//

#ifndef UDG_HEXENCODE_HPP
#define UDG_HEXENCODE_HPP

#include <string>
#include <string.h>
#include <cstdio>

namespace udg {
    std::string hex_encode(const std::string& src) {
        std::string out = "0x";

        for (std::string::const_iterator it = src.begin();
                it != src.end();
                ++it) {
            char hex[3] = {};
            snprintf(hex, 3, "%02x", (unsigned int) *it);
            out.append(hex);
        }

        return out;
    }

    std::string hex_encode(const uint8_t* src, size_t len) {
        std::string out = "0x";

        for (const uint8_t* it = src;
             it != src + len;
             ++it) {
            char hex[3] = {};
            snprintf(hex, 3, "%02x", (unsigned int) *it);
            out.append(hex);
        }

        return out;
    }
}

#endif //UDG_HEXENCODE_HPP
