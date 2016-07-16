//
// Created by nsamson on 7/4/16.
//

#ifndef UDG_STRTOULL_HPP
#define UDG_STRTOULL_HPP

#include <string>

namespace udg {
    unsigned long long
            strtoull(const char *nptr, char **endptr, int base);

    long long int
            strtoll(const char *nptr, char **endptr, int base);

    std::string ulltostr(unsigned long long inp);
    std::string lltostr(long long inp);

    template <typename T>
    T byte_swap(T data) {
        T out;

        uint8_t* out_ptr = reinterpret_cast<uint8_t*>(&out);
        uint8_t* in_ptr = reinterpret_cast<uint8_t*>(&data);

        for (size_t i = 0; i < sizeof(T); i++) {
            out_ptr[i] = in_ptr[sizeof(T) - 1 - i];
        }

        return out;
    }
}
#endif //UDG_STRTOULL_HPP
