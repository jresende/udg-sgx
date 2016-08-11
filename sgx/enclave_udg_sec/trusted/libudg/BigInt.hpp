/*
 * BigInt.hpp
 *
 *  Created on: Aug 8, 2016
 *      Author: nsamson
 */

#ifndef SGX_ENCLAVE_UDG_SEC_TRUSTED_BIGINT_HPP_
#define SGX_ENCLAVE_UDG_SEC_TRUSTED_BIGINT_HPP_

#include "byte_array.hpp"
#include "hex_encode.hpp"
#include <algorithm>
#include <stdint.h>
#include <stdexcept>
#include "io.hpp"
#include <string>

namespace udg {

	template <unsigned BitLength>
	class BigInt {

		static_assert(BitLength % 64 == 0 && BitLength != 0, "Bit length must be a multiple of 64 and greater than 0");
		FixedSizedByteArray<BitLength / 8> _data;

	public:

		const static unsigned size = BitLength / 8;
		const static unsigned bits = BitLength;
		const static unsigned words = BitLength / 16;
		const static unsigned dwords = BitLength / 32;
		const static unsigned qwords = BitLength / 64;

		const static BigInt<BitLength> ZERO;
		const static BigInt<BitLength> ONE;

		BigInt() = default;
		BigInt(const BigInt&) = default;
		BigInt(const std::string& str) {
			std::string cpy(str);
			if (str.substr(0, 2).compare("0x") == 0) {
				cpy = cpy.substr(2);
			}
			if (cpy.length() > BigInt::size * 2) {
				throw std::invalid_argument("String too big for integer.");
			}

			if (cpy.length() < BigInt::size * 2) {
				cpy.insert(cpy.begin(), BigInt::size * 2 - cpy.length(), '0');
			}

			auto bin = udg::hex_decode(cpy);
			this->_data = FixedSizedByteArray<BigInt::size>(bin.begin(), bin.end());
			this->_data.reverse_in_place();
		}

		explicit BigInt(const char* str) {
			std::string cpy(str);
			if (cpy.substr(0, 2).compare("0x") == 0) {
				cpy = cpy.substr(2);
			}
			if (cpy.length() > BigInt::size * 2) {
				throw std::invalid_argument("String too big for integer.");
			}

			if (cpy.length() < BigInt::size * 2) {
				cpy.insert(cpy.begin(), BigInt::size * 2 - cpy.length(), '0');
			}

			auto bin = udg::hex_decode(cpy);
			this->_data = FixedSizedByteArray<BigInt::size>(bin.begin(), bin.end());
			this->_data.reverse_in_place();
		}

		template <typename BidirectionalIterator>
		BigInt(BidirectionalIterator begin, BidirectionalIterator end, bool big_endian=false) {
			if (std::distance(begin, end) > BigInt::size) {
				throw std::invalid_argument("Iterators too big to instantiate BigInt");
			}

			if (big_endian) {
				std::reverse_copy(begin, end, this->_data.begin());
			} else {
				std::copy(begin, end, this->_data.begin());
			}
		}

		BigInt(uint64_t start) {
			this->_data = FixedSizedByteArray<BigInt::size>::template from<uint64_t>(start);
		}

		BigInt(const FixedSizedByteArray<BigInt::size>& ref) : _data(ref) {}

		static BigInt random() {
			return BigInt(FixedSizedByteArray<BigInt::size>::random());
		}

		BigInt& operator=(const BigInt&) = default;

		FixedSizedByteArray<BigInt::size> get_data() const {
			return this->_data;
		}

		uint64_t to_uint64_t() const {
			return _data.template reinterpret<uint64_t>();
		}

		bool to_bool() const {
			return (*this != BigInt::ZERO);
		}

		template <unsigned M>
		operator BigInt<M>() const {
			if (M > BigInt::bits) {
//				io::cdebug << "Bigger";
				return BigInt<M>(this->to_string());
			} else {
//				io::cdebug << "Smaller";
				return BigInt<M>(_data.template slice<BigInt<M>::size>(0));
			}
		}

		bool operator ==(const BigInt& that) const {
			return this->_data == that._data;
		}

		bool operator !=(const BigInt& that) const {
			return !(*this == that);
		}

		bool operator >(const BigInt& that) const {
			unsigned highest_this = 0;
			unsigned highest_that = 0;

			for (unsigned i = 0; i < BigInt::size; i++) {
				if (this->_data[i] != 0) {
					highest_this = i;
				}

				if (that._data[i] != 0) {
					highest_that = i;
				}
			}

			if (highest_this > highest_that) {
				return true;
			} else if (highest_this < highest_that) {
				return false;
			}

			for (long int i = BigInt::size - 1; i > 0; i--) {
				if (this->_data[i] > that._data[i]) {
					return true;
				} else if (this->_data[i] < that._data[i]) {
					return false;
				}
			}

			return false;
		}
		bool operator <(const BigInt& that) const {
			return (*this != that) && !(*this > that);
		}

		bool operator <=(const BigInt& that) const {
			return !(*this > that);
		}

		bool operator >=(const BigInt& that) const {
			return !(*this < that);
		}

		BigInt operator +(const BigInt& that) const {
			FixedSizedByteArray<BigInt::size> out_data;

			bool carry = false;

			for (unsigned i = 0; i < BigInt::qwords; i++) {
				uint64_t lhs = this->_data.template reinterpret_at<uint64_t>(i * 8);
				uint64_t rhs = that._data.template reinterpret_at<uint64_t>(i * 8);
				uint64_t out = lhs + rhs;

				if (carry) {
					out++;
				}

				carry = out < lhs || out < rhs;

				auto slice_dat = FixedSizedByteArray<8>::template from<uint64_t>(out);
				std::copy(slice_dat.begin(), slice_dat.end(), out_data.begin() + (i * 8));
			}

			return BigInt(out_data);
		}

		BigInt operator -(const BigInt& that) const {
			return *this + -(that);
		}

#ifdef PEASANT_MULT
		BigInt operator *(const BigInt& that) const {

			BigInt<BigInt::bits> smallest = (*this < that) ? *this : that;
			BigInt<BigInt::bits> other = (that == smallest) ? *this : that;
			BigInt<BigInt::bits> total;

			for (unsigned i = 0; i < BigInt::bits * 2; i++) {
				if (smallest.is_bit_set(i)) {
					total += other;
					other <<= 1;
				} else {
					// Detect length of run
					unsigned cnt = 0;
					while (i < BigInt::bits * 2 && !smallest.is_bit_set(i)) {
						i++;
						cnt++;
					}
					i--;

					other <<= cnt;
				}
			}

			return total;
		}
#else
		BigInt operator *(const BigInt& that) const {

			BigInt<BigInt::bits> total;
			BigInt<BigInt::bits> temp;

			for (unsigned i = 0; i < BigInt::dwords; i++) {
				for (unsigned j = 0; j + i < BigInt::dwords; j++) {

					uint64_t word_i = this->_data.template reinterpret_at<uint32_t>(i * 4);
					uint64_t word_j = that._data.template reinterpret_at<uint32_t>(j * 4);
					uint64_t word_o = word_i * word_j;

					temp._data.clear();
					if (j + i != BigInt::dwords - 1) {
						temp._data.template slice_ref<8>((i + j) * 4) |= FixedSizedByteArray<8>::template from<uint64_t>(word_o);
					} else {
						temp._data.template slice_ref<4>((i + j) * 4) |= FixedSizedByteArray<4>::template from<uint32_t>((uint32_t)word_o);
					}

//					io::cdebug << i << j;
//					io::cdebug << "Temporaries";
//					io::cdebug << BigInt<64>(word_i).to_string()
//							<< BigInt<64>(word_j).to_string()
//							<< BigInt<64>(word_o).to_string();
//
//					io::cdebug << temp.to_string();


					total += temp;

				}
			}

			return total;
		}
#endif

		static void divmod(BigInt dividend, BigInt divisor, BigInt& quotient, BigInt& remainder) {
			if (divisor == BigInt::ZERO) {
				throw std::invalid_argument("Division by zero.");
			} else if (divisor > dividend) {
				quotient = 0;
				remainder = dividend;
				return;
			} else if (dividend == divisor) {
				quotient = 1;
				remainder = 0;
				return;
			}

			for (unsigned i = BigInt::bits; i > 0; i--) {
				auto n = i - 1;
				remainder<<= 1;
				remainder.set_bit(0, dividend.is_bit_set(n) ? 1 : 0);
				if (remainder >= divisor) {
					remainder -= divisor;
					quotient.set_bit(n, 1);
				}
			}

			return;
		}

		static BigInt pow(BigInt x, unsigned n) {
			if (x > BigInt::bits) {
				return BigInt::ZERO;
			} else if (x == 0) {
				return BigInt::ONE;
			}

			BigInt y = 1;

			while (n > 1) {
				if (n & 1) {
					y *= x;
					x *= x;
					n = (n - 1) / 2;
				} else {
					x *= x;
					n /= 2;
				}
			}

			return x * y;

		}

		BigInt pow(unsigned n) const {
			return BigInt::pow(*this, n);
		}

		BigInt operator /(const BigInt& that) const {
			BigInt q, r;
			BigInt::divmod(*this, that, q, r);
			return q;
		}

		BigInt operator <<(uint64_t num) const {
			if (num >= BigInt::bits) {
				return BigInt();
			} else if (num == 0) {
				return BigInt(*this);
			}

			BigInt out;

			std::string rep = "";
			for (unsigned i = 0; i < BigInt::bits; i++) {
				rep.append(1, (this->is_bit_set(i) ? '1' : '0'));
			}

			rep.insert(rep.begin(), num, '0');

			for (unsigned i = 0; i < BigInt::bits; i++) {
				out.set_bit(i, rep.at(i) == '1' ? 1 : 0);
			}

			return out;
		}

		BigInt operator >>(uint64_t num) const {
			if (num >= BigInt::bits) {
				return BigInt();
			} else if (num == 0) {
				return BigInt(*this);
			}

			BigInt out;

			std::string rep = "";
			for (unsigned i = 0; i < BigInt::bits; i++) {
				rep.append(1, (this->is_bit_set(i) ? '1' : '0'));
			}

			rep.append(num, '0');
			rep.erase(rep.begin(), rep.begin() + num);

			for (unsigned i = 0; i < BigInt::bits; i++) {
				out.set_bit(i, rep.at(i) == '1' ? 1 : 0);
			}

			return out;
		}

		BigInt operator |(const BigInt& that) const {
			BigInt copy(*this);
			copy |= that;
			return copy;
		}

		BigInt operator &(const BigInt& that) const {
			BigInt copy(*this);
			copy &= that;
			return copy;
		}

		BigInt operator ^(const BigInt& that) const {
			BigInt copy(*this);
			copy ^= that;
			return copy;
		}

		BigInt operator %(const BigInt& that) const {
			BigInt q, r;
			BigInt::divmod(*this, that, q, r);
			return r;
		}

		BigInt& operator +=(const BigInt& that) {
			*this = *this + that;
			return *this;
		}

		BigInt& operator -=(const BigInt& that) {
			*this = *this - that;
			return *this;
		}

		BigInt& operator *=(const BigInt& that) {
			*this = *this * that;
			return *this;
		}

		BigInt& operator /=(const BigInt& that) {
			*this = *this / that;
			return *this;
		}

		BigInt& operator <<=(uint64_t that) {
			*this = *this << that;
			return *this;
		}

		BigInt& operator >>=(uint64_t that) {
			*this = *this >> that;
			return *this;
		}

		BigInt& operator |=(const BigInt& that) {
			this->_data |= that._data;
			return *this;
		}
		BigInt& operator &=(const BigInt& that) {
			this->_data &= that._data;
			return *this;
		}
		BigInt& operator ^=(const BigInt& that) {
			this->_data ^= that._data;
			return *this;
		}

		BigInt& operator %=(const BigInt& that) {
			*this = *this % that;
			return *this;
		}

		BigInt& operator ++() {
			*this -= 1;
			return *this;
		}

		BigInt& operator --() {
			*this += 1;
			return *this;
		}

		BigInt operator++(int) {
			BigInt tmp(*this);
			operator++();
			return tmp;
		}

		BigInt operator--(int) {
			BigInt tmp(*this);
			operator--();
			return tmp;
		}

		BigInt operator -() const {
			return (~(*this)) + 1;
		}

		BigInt operator ~() const {
			BigInt out;

			for (unsigned i = 0; i < BigInt::size; ++i) {
				out._data[i] = ~(this->_data[i]);
			}

			return out;
		}

		FixedSizedByteArray<BigInt::size> be_serialize() const {
			return _data.reverse();
		}

		FixedSizedByteArray<BigInt::size> to_hash() const {
			return _data;
		}

		bool is_bit_set(unsigned index) const {
			return (this->_data[index / 8] & (0x1U << (index % 8))) != 0;
		}

		void set_bit(unsigned index, uint8_t i) {
			auto val = this->_data[index / 8];
			val |= (i << (index % 8));
			this->_data[index / 8] = val;
		}

		std::string to_string() const {
			return this->_data.reverse().to_string();
		}

		rlp::rlpvec to_rlp() const {
			return this->_data.reverse().to_rlp();
		}

	};

	template <unsigned BitLength>
	const udg::template BigInt<BitLength> BigInt<BitLength>::ONE = 1;

	template <unsigned BitLength>
	const udg::template BigInt<BitLength> BigInt<BitLength>::ZERO = 0;

	using uint256 = BigInt<256>;
	using uint320 = BigInt<320>;
	using uint512 = BigInt<512>;
}

#endif /* SGX_ENCLAVE_UDG_SEC_TRUSTED_BIGINT_HPP_ */
