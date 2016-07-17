/*
 * byte_array.hpp
 *
 *  Created on: Jul 16, 2016
 *      Author: nsamson
 */

#ifndef SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_CRYPTO_BYTE_ARRAY_HPP_
#define SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_CRYPTO_BYTE_ARRAY_HPP_

#include <stdint.h>
#include <string.h>
#include <string>
#include <algorithm>
#include "hex_encode.hpp"

namespace udg {

	template <unsigned long int N>
	class FixedSizedByteArray {

		uint8_t _data[N];

	public:

		FixedSizedByteArray() { memset(this->_data, 0, N); }
		FixedSizedByteArray(const uint8_t data[], size_t len) {
			size_t to_copy = len > N ? N : len;

			memset(this->_data, 0, N);
			memcpy(this->_data, data, to_copy);
		}

		FixedSizedByteArray(uint8_t rep) {
			memset(this->_data, rep, N);
		}

		FixedSizedByteArray(const FixedSizedByteArray& that) {
			std::copy(that.begin(), that.end(), this->begin());
		}

		template <typename _InputIterator>
		FixedSizedByteArray(_InputIterator begin, _InputIterator end) {
			memset(this->_data, 0, N);

			for (size_t cnt = 0; begin != end && cnt < N; ++begin, cnt++) {
				this->_data[cnt] = *begin;
			}
		}

		FixedSizedByteArray& operator=(const FixedSizedByteArray& that) {
			std::copy(that.begin(), that.end(), this->begin());
			return *this;
		}

		typedef uint8_t* iterator;
		typedef const uint8_t* const_iterator;

		static const unsigned int size = N;

		const uint8_t& operator[](size_t index) const { return _data[index]; }
		uint8_t& operator[](size_t index) {return _data[index];}

		const uint8_t* data() const { return _data; }
		uint8_t* data() { return _data; }

		iterator begin() { return _data; };
		const_iterator begin() const {return _data;};

		iterator end() {return _data + N; };
		const_iterator end() const { return _data + N; }

		bool operator==(const FixedSizedByteArray& that) const {
			return std::equal(this->begin(), this->end(), that.begin());
		}
		bool operator!=(const FixedSizedByteArray& that) const {
			return !(*this == that);
		}

		FixedSizedByteArray operator^(const FixedSizedByteArray& that) const {
			FixedSizedByteArray out;

			for (size_t i = 0; i < FixedSizedByteArray::size; i++) {
				out[i] = this->_data[i] ^ that[i];
			}

			return out;
		}

		FixedSizedByteArray operator|(const FixedSizedByteArray& that) const {
			FixedSizedByteArray out;

			for (size_t i = 0; i < FixedSizedByteArray::size; i++) {
				out[i] = this->_data[i] | that[i];
			}

			return out;
		}

		FixedSizedByteArray operator&(const FixedSizedByteArray& that) const {
			FixedSizedByteArray out;

			for (size_t i = 0; i < FixedSizedByteArray::size; i++) {
				out[i] = this->_data[i] & that[i];
			}

			return out;
		}

		// Truncates if M larger than N
		template <unsigned long int M>
		static FixedSizedByteArray right_zpad(const FixedSizedByteArray<M>& that) {

			// Zero-initialized by default; no need to actually pad.
			FixedSizedByteArray out;

			if (M >= N) {
				for (size_t i = 0; i < N; i++) {
					out[i] = that[i];
				}
			} else {
				for (size_t i = 0; i < M; i++) {
					out[i] = that[i];
				}
			}

			return out;
		}

		// Truncates in the opposite direction of right pad
		template <unsigned long int M>
		static FixedSizedByteArray left_zpad(const FixedSizedByteArray<M>& that) {
			// Zero-initialized by default; no need to actually pad.
			FixedSizedByteArray out;

			if (M >= N) {
				for (size_t i = 0; i < N; i++) {
					out[i] = that[i + (M - N)];
				}
			} else {
				for (size_t i = 0; i < M; i++) {
					out[i + (N - M)] = that[i];
				}
			}

			return out;
		}

		std::string to_string() const {
			return hex_encode(this->_data, FixedSizedByteArray::size);
		}

		void clear() {
			memset(this->_data, 0, N);
		}

	};

	using h128 = FixedSizedByteArray<16>;
	using h256 = FixedSizedByteArray<32>;
	using h512 = FixedSizedByteArray<64>;
	using h1024 = FixedSizedByteArray<128>;

}


#endif /* SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_CRYPTO_BYTE_ARRAY_HPP_ */
