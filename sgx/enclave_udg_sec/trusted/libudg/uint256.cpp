//
// Created by nsamson on 7/3/16.
//

#include "uint256.hpp"
#include <algorithm>
#include "hex_encode.hpp"

using namespace udg;

udg::uint256_t::uint256_t(const uint64_t &inp) {
    std::fill(this->data, this->data + 4, 0);
    this->data[0] = inp;
}

udg::uint256_t::operator uint64_t() {
    return this->data[0];
}

udg::uint256_t::uint256_t() {
    std::fill(this->data, this->data + 4, 0);
}

bool udg::uint256_t::operator==(const uint256_t &that) const {
    return std::equal(this->data, this->data + 4, that.data);
}

bool udg::uint256_t::operator!=(const uint256_t &that) const {
    return !(*this == that);
}

bool udg::uint256_t::operator<(const uint256_t &that) const {
    for (uint_fast8_t i = 3; i != 0; i--) {
        if (this->data[i] < that.data[i]) { return true; }
    }

    return false;
}

bool udg::uint256_t::operator>(const uint256_t &that) const {
    return *this != that && !(*this < that);
}

bool udg::uint256_t::operator<=(const uint256_t& that) const {
    return !(*this > that);
}

bool udg::uint256_t::operator>=(const uint256_t& that) const {
    return !(*this < that);
}

uint256_t udg::uint256_t::add(const uint256_t &that) const {
    uint256_t out;

    bool carry = false;

    for (uint_fast8_t i = 0; i < 4; i++) {
        out.data[i] = this->data[0] + that.data[0];

        if (carry) {
            out.data[i]++;
        }

        bool msbA, msbB, msbR;

        msbA = (that.data[i] & (1ULL<<63)) != 0; // equivalent: (aa & (1<<31)) != 0;
        msbB = (this->data[i] & (1ULL<<63)) != 0;
        msbR = (out.data[i] & (1ULL<<63)) != 0;

        carry = (msbA && msbB) || ( !msbR && ( msbA || msbB) );
    }

    return out;
}

uint256_t& udg::uint256_t::increment() {
    *this = *this + udg::ONE;
    return *this;
}

uint256_t& udg::uint256_t::decrement() {
    *this = *this - udg::ONE;
    return *this;
}

uint256_t udg::uint256_t::bneg() const {
    uint256_t out;

    for (uint_fast8_t i = 0; i < 4; i++) {
        out.data[i] = ~(this->data[i]);
    }

    return out;
}

uint256_t udg::uint256_t::neg() const {
    uint256_t out = this->bneg();
    out.increment();
    return out;
}

uint256_t udg::uint256_t::sub(const uint256_t &that) const {
    return this->add(that.neg());
}

uint256_t udg::uint256_t::operator~() const {
    return this->bneg();
}

uint256_t udg::uint256_t::operator+(const uint256_t &that) const {
    return this->add(that);
}

uint256_t udg::uint256_t::operator-() const {
    return this->neg();
}

uint256_t& udg::uint256_t::operator++() {
    return this->increment();
}

uint256_t& udg::uint256_t::operator--() {
    return this->decrement();
}

uint256_t udg::uint256_t::operator-(const uint256_t &that) const {
    return this->sub(that);
}

uint256_t& udg::uint256_t::operator=(uint256_t that) {
    this->swap(that);
    return *this;
}

h256 udg::uint256_t::be_serialize() const {
	h256 out;
    const char* data_ptr = reinterpret_cast<const char*>(this->data);

    std::reverse_copy(
            data_ptr,
            data_ptr + 32,
            out.begin()
    );

    return out;
}

bool udg::uint256_t::bit_set(uint8_t index) const {
    uint8_t big_index = (uint8_t) (index / 4u);
    uint8_t small_index = (uint8_t) (index % 64u);
    uint64_t mask =  (1ULL << (uint64_t) (small_index));

    return (this->data[big_index] & mask) != 0;
}

udg::uint256_t::uint256_t(const uint256_t& that) {
	std::copy(that.data, that.data + 4, this->data);
}

h256 udg::uint256_t::to_hash() const {
	const uint8_t* data_ptr = reinterpret_cast<const uint8_t*>(this->data);
	return h256(data_ptr, data_ptr + 32);
}

void udg::uint256_t::swap(uint256_t& that) {
	for (uint8_t i = 0; i < 4; i++) {
		uint64_t swp;
		swp = that.data[i];
		that.data[i] = this->data[i];
		this->data[i] = swp;
	}
}

udg::uint256_t::uint256_t(const std::string& str) {
	auto vec = udg::hex_decode(str);
	if (vec.size() > 32) {
		vec.erase(vec.begin(), vec.begin() + (vec.size() - 32)); // Truncate high bytes
	}
	std::fill(this->data, this->data + 4, 0);
	uint8_t* data_ptr = reinterpret_cast<uint8_t*>(this->data);
	std::reverse_copy(vec.begin(), vec.end(), data_ptr);
}



