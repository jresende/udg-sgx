/*
 * array.hpp
 *
 *  Created on: Aug 7, 2016
 *      Author: nsamson
 */

#ifndef SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_ARRAY_HPP_
#define SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_ARRAY_HPP_

#include <stdint.h>
#include <string.h>
#include <string>
#include <stdexcept>
#include <algorithm>
#include "hex_encode.hpp"
#include "ethereum/rlp.hpp"
#include <sgx_trts.h>

namespace udg {

	template <typename T, unsigned long int N>
	class Array {

		T _data[N];

	public:

		Array() { memset(this->_data, 0, N); }
		Array(const T data[], size_t len) {
			size_t to_copy = len > N ? N : len;
			std::copy(data, data + to_copy, _data);
		}

		Array(const T& rep) {
			std::fill(_data, _data + N, rep);
		}

		Array(const Array& that) {
			std::copy(that.begin(), that.end(), this->begin());
		}

		template <typename _InputIterator>
		Array(_InputIterator begin, _InputIterator end) {

			for (size_t cnt = 0; begin != end && cnt < N; ++begin, cnt++) {
				this->_data[cnt] = *begin;
			}
		}

		Array& operator=(const Array& that) {
			std::copy(that.begin(), that.end(), this->begin());
			return *this;
		}

		typedef T* iterator;
		typedef const T* const_iterator;

		static const unsigned int size = N;

		const T& operator[](size_t index) const { return _data[index]; }
		T& operator[](size_t index) {return _data[index];}

		const T* data() const { return _data; }
		T* data() { return _data; }

		iterator begin() { return _data; };
		const_iterator begin() const {return _data;};

		iterator end() {return _data + N; };
		const_iterator end() const { return _data + N; }

		bool operator==(const Array& that) const {
			return std::equal(this->begin(), this->end(), that.begin());
		}
		bool operator!=(const Array& that) const {
			return !(*this == that);
		}

		void clear() {
			std::fill(this->begin(), this->end(), T());
		}

		Array& reverse() {
			std::reverse(this->begin(), this->end());
			return *this;
		}

		template <unsigned long int M>
		FixedSizedByteArray<M> slice(uint64_t at) {
			if (at + M > N) {
				throw std::invalid_argument("Slice cannot be larger than array.");
			}

			return FixedSizedByteArray<M>(this->begin() + at, this->begin() + at + M);
		}

		Array reverse() const {
			Array out;
			std::reverse_copy(this->begin(), this->end(), out.begin());
			return out;
		}

	};

}



#endif /* SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_ARRAY_HPP_ */
