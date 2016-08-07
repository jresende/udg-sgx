//
// Created by nsamson on 7/3/16.
//

#ifndef UDG_UINT256_HPP
#define UDG_UINT256_HPP

#include <stdint.h>
#include <string>
#include <cstddef>
#include <algorithm>
#include "intconv.hpp"
#include "byte_array.hpp"
#include "ethereum/rlp.hpp"

namespace udg {

    class uint256_t : public rlp::RLPConvertable {
        uint64_t data[4];

    public:

        // InputIterator represents some iterator following
        // the concept such that when dereferenced, the dereferenced type is a byte
        // Assumption is that input is big-endian
        template <typename ForwardIterator>
        uint256_t(ForwardIterator begin, ForwardIterator end);
        uint256_t(const uint64_t& inp);
        uint256_t();
        uint256_t(const std::string& str);

        uint256_t& decrement();
        uint256_t& increment();
        uint256_t add(const uint256_t& that) const;
        uint256_t sub(const uint256_t& that) const;
        uint256_t bneg() const;
        uint256_t neg() const;


        operator uint64_t() const;

        bool operator ==(const uint256_t& that) const;
        bool operator !=(const uint256_t& that) const;
        bool operator >(const uint256_t& that) const;
        bool operator <(const uint256_t& that) const;
        bool operator <=(const uint256_t& that) const;
        bool operator >=(const uint256_t& that) const;

        uint256_t& operator ++();
        uint256_t& operator --();

        uint256_t operator +(const uint256_t& that) const;
        uint256_t operator -(const uint256_t& that) const;
        uint256_t operator -() const;
        uint256_t operator ~() const;

        h256 be_serialize() const;
        h256 to_hash() const;

        bool bit_set(uint8_t index) const;

        uint256_t(const uint256_t&);
        uint256_t& operator=(uint256_t);

        void swap(uint256_t&);

    };

    const static uint256_t ZERO = uint256_t(0);
    const static uint256_t ONE = uint256_t(1);



    template <typename ForwardIterator>
    uint256_t::uint256_t(ForwardIterator begin, ForwardIterator end) {
        std::fill(this->data, this->data + 4, 0);
        uint8_t* data_ptr = reinterpret_cast<uint8_t*>(this->data);
        std::reverse_copy(begin, end, data_ptr);
    }

}

#endif //UDG_UINT256_HPP
