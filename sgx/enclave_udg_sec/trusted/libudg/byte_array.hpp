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
#include <stdexcept>
#include <algorithm>
#include "hex_encode.hpp"
#include "ethereum/rlp.hpp"
#include <sgx_trts.h>

namespace udg {

	template <unsigned long int N, unsigned long int Len>
	class ByteArrayRef;

	template <unsigned long int N>
	class FixedSizedByteArray {

		uint8_t _data[N];

	public:

		FixedSizedByteArray() { memset(this->_data, 0, N); }
		FixedSizedByteArray(const uint8_t data[], size_t len, bool lzpad = false) {
			memset(this->_data, 0, N);
			size_t to_copy = len > N ? N : len;
			if (!lzpad || to_copy >= N) {
				memcpy(this->_data, data, to_copy);
			} else {
				memcpy(this->_data + N - to_copy, data, to_copy);
			}
		}

		FixedSizedByteArray(uint8_t rep) {
			memset(this->_data, rep, N);
		}

		FixedSizedByteArray(const FixedSizedByteArray& that) {
			std::copy(that.begin(), that.end(), this->begin());
		}

		FixedSizedByteArray(const std::string& str) {
			std::vector<uint8_t> bytes = udg::hex_decode(str);

			auto begin = bytes.begin();
			auto end = bytes.end();
			for (size_t cnt = 0; begin != end && cnt < N; ++begin, cnt++) {
				this->_data[cnt] = *begin;
			}
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

		uint8_t operator[](size_t index) const { return _data[index]; }
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

		FixedSizedByteArray operator^=(const FixedSizedByteArray& that) {

			for (size_t i = 0; i < FixedSizedByteArray::size; i++) {
				this->_data[i] ^= that[i];
			}

			return *this;
		}

		FixedSizedByteArray operator|=(const FixedSizedByteArray& that) {
			for (size_t i = 0; i < FixedSizedByteArray::size; i++) {
				this->_data[i] |= that[i];
			}

			return *this;
		}

		FixedSizedByteArray operator&=(const FixedSizedByteArray& that) {
			for (size_t i = 0; i < FixedSizedByteArray::size; i++) {
				this->_data[i] &= that[i];
			}

			return *this;
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

		bool operator>(const FixedSizedByteArray& that) const {
			for (uint8_t i = 0; i < N; i++) {
				if (this->_data[i] > that[i]) {
					return true;
				}
			}

			return false;
		}

		bool operator<(const FixedSizedByteArray& that) const {
			for (uint8_t i = 0; i < N; i++) {
				if (this->_data[i] < that[i]) {
					return true;
				}
			}

			return false;
		}

		bool operator>=(const FixedSizedByteArray& that) const {
			return !(*this < that);
		}

		bool operator<=(const FixedSizedByteArray& that) const {
			return !(*this > that);
		}

		static FixedSizedByteArray random() {
			FixedSizedByteArray out;
			sgx_read_rand(out.data(), N);
			return out;
		}

		FixedSizedByteArray& reverse() {
			std::reverse(this->begin(), this->end());
			return *this;
		}

		rlp::rlpvec to_rlp() const {
			uint32_t i;
			for (i = 0; i < N; i++) {
				if (_data[i] != 0) {
					break;
				}
			}

			return rlp::to_rlp((const char*)this->_data + i, (size_t) N - i);
		}

		rlp::rlpvec to_rlp_with_zeroes() const {
			return rlp::to_rlp((const char*)this->data(), FixedSizedByteArray::size);
		}

		template <unsigned long int M>
		ByteArrayRef<N, M> slice_ref(uint64_t at);

		template <unsigned long int M>
		FixedSizedByteArray<M> slice(uint64_t at) {
			if (at + M > N) {
				throw std::invalid_argument("Slice cannot be larger than array.");
			}

			return FixedSizedByteArray<M>(this->begin() + at, this->begin() + at + M);
		}

		template <typename T>
		T reinterpret() const {
			static_assert(sizeof(T) <= N, "Object to copy data into must be same or smaller size than array.");
			T out;
			memcpy(&out, this->_data, sizeof(T));
			return out;
		}

		template <typename T>
		T reinterpret_at(uint64_t at) {
			return this->slice_ref<sizeof(T)>(at).reinterpret<T>();
		}

		template <typename T>
		static FixedSizedByteArray from(const T& inp) {
			static_assert(sizeof(T) <= N, "Object to arrayify must be of same or smaller size than array.");
			const uint8_t* obj_dat = reinterpret_cast<const uint8_t*>(&inp);
			return FixedSizedByteArray(obj_dat, obj_dat + sizeof(T));
		}

		FixedSizedByteArray reverse() const {
			FixedSizedByteArray out;
			std::reverse_copy(this->begin(), this->end(), out.begin());
			return out;
		}

	};

	template <unsigned long int N, unsigned long int Len>
	class ByteArrayRef {
		FixedSizedByteArray<N>* _ref;
		uint64_t offset;

	public:

		const static unsigned long int base_size = N;
		const static unsigned long int size = Len;

		ByteArrayRef(FixedSizedByteArray<N>& that, uint64_t offset = 0)
			: _ref(&that), offset(offset) {}

		ByteArrayRef(const ByteArrayRef& that) : _ref(that._ref), offset(that.offset) {}
		ByteArrayRef& operator=(ByteArrayRef that) {
			std::swap(this->_ref, that._ref);
			std::swap(offset, that.offset);

			return *this;
		}

		typedef uint8_t* iterator;
		typedef const uint8_t* const_iterator;

		uint8_t operator[](size_t index) const { return _ref[index + offset]; }
		uint8_t& operator[](size_t index) { return _ref[index + offset]; }

		const uint8_t* data() const { return _ref->data() + offset; }
		uint8_t* data() { return _ref->data() + offset; }

		iterator begin() { return this->data(); };
		const_iterator begin() const {return this->data();};

		iterator end() {return this->begin() + Len; };
		const_iterator end() const { return this->begin() + Len; }

		bool operator==(const FixedSizedByteArray<Len>& that) const {
			return std::equal(this->begin(), this->end(), that.begin());
		}
		bool operator!=(const FixedSizedByteArray<Len>& that) const {
			return !(*this == that);
		}

		bool operator==(const ByteArrayRef& that) const {
			return std::equal(this->begin(), this->end(), that.begin());
		}
		bool operator!=(const ByteArrayRef& that) const {
			return !(*this == that);
		}

		FixedSizedByteArray<Len> operator^(const FixedSizedByteArray<Len>& that) const {
			FixedSizedByteArray<Len> out;

			for (size_t i = offset; i < offset + Len; i++) {
				out[i] = this->_ref->data()[i] ^ that[i - offset];
			}

			return out;
		}

		ByteArrayRef& operator^=(const FixedSizedByteArray<Len>& that) {

			for (size_t i = offset; i < offset + Len; i++) {
				this->_ref->data()[i] ^= that[i - offset];
			}

			return *this;
		}

		ByteArrayRef& operator|=(const FixedSizedByteArray<Len>& that) {

			for (size_t i = offset; i < offset + Len; i++) {
				this->_ref->data()[i] |= that[i - offset];
			}

			return *this;
		}

		ByteArrayRef& operator&=(const FixedSizedByteArray<Len>& that) {

			for (size_t i = offset; i < offset + Len; i++) {
				this->_ref->data()[i] &= that[i - offset];
			}

			return *this;
		}

		ByteArrayRef& operator^=(const ByteArrayRef& that) {

			for (size_t i = 0; i < Len; i++) {
				this->data()[i] ^= that.data()[i];
			}

			return *this;
		}

		ByteArrayRef& operator|=(const ByteArrayRef& that) {

			for (size_t i = 0; i < Len; i++) {
				this->data()[i] |= that.data()[i];
			}

			return *this;
		}

		ByteArrayRef& operator&=(const ByteArrayRef& that) {

			for (size_t i = 0; i < Len; i++) {
				this->data()[i] &= that.data()[i];
			}

			return *this;
		}

		std::string to_string() const {
			return hex_encode(this->data(), ByteArrayRef::size);
		}

		void clear() {
			memset(this->data(), 0, Len);
		}

		bool operator>(const FixedSizedByteArray<Len>& that) const {
			for (uint8_t i = 0; i < Len; i++) {
				if (this->_ref->data()[i + offset] > that[i]) {
					return true;
				}
			}

			return false;
		}

		bool operator<(const FixedSizedByteArray<Len>& that) const {
			for (uint8_t i = 0; i < Len; i++) {
				if (this->_ref->data()[i + offset] < that[i]) {
					return true;
				}
			}

			return false;
		}

		bool operator>=(const FixedSizedByteArray<Len>& that) const {
			return !(*this < that);
		}

		bool operator<=(const FixedSizedByteArray<Len>& that) const {
			return !(*this > that);
		}

		bool operator>(const ByteArrayRef& that) const {
			for (uint8_t i = 0; i < Len; i++) {
				if (this->_ref->data()[i + offset] > that[i]) {
					return true;
				}
			}

			return false;
		}

		bool operator<(const ByteArrayRef& that) const {
			for (uint8_t i = 0; i < Len; i++) {
				if (this->_ref->data()[i + offset] < that[i]) {
					return true;
				}
			}

			return false;
		}

		bool operator>=(const ByteArrayRef& that) const {
			return !(*this < that);
		}

		bool operator<=(const ByteArrayRef& that) const {
			return !(*this > that);
		}

		ByteArrayRef& reverse() {
			std::reverse(this->begin(), this->end());
			return *this;
		}

		rlp::rlpvec to_rlp() const {
			uint32_t i;
			for (i = 0; i < Len; i++) {
				if (data()[i] != 0) {
					break;
				}
			}

			return rlp::to_rlp((const char*)this->data() + i, (size_t) Len - i);
		}

		rlp::rlpvec to_rlp_with_zeroes() const {
			return rlp::to_rlp((const char*)this->data(), ByteArrayRef::size);
		}

		template <unsigned long int M>
		ByteArrayRef<N, M> slice_ref(uint64_t at) {
			if (at + M > Len) {
				throw std::invalid_argument("Slice cannot be larger than array.");
			}

			return ByteArrayRef<N, M>(this->_ref, offset + at);
		}

		template <typename T>
		T reinterpret() const {
			static_assert(sizeof(T) <= Len, "Object to copy data into must be same or smaller size than array.");
			T out;
			memcpy(&out, this->data(), sizeof(T));
			return out;
		}

		template <typename T>
		T reinterpret_at(uint64_t at) {
			return this->slice_ref<sizeof(T)>(at).reinterpret<T>();
		}

		FixedSizedByteArray<Len> unslice() const {
			return FixedSizedByteArray<Len>(this->begin(), this->end());
		}

	};

	template <unsigned long int N>
	template <unsigned long int M>
	inline
	ByteArrayRef<N, M> FixedSizedByteArray<N>::slice_ref(uint64_t at) {
		if (at + M > N) {
			throw std::invalid_argument("Slice cannot be larger than array.");
		}

		return ByteArrayRef<N, M>(*this, at);
	}

	using h128 = FixedSizedByteArray<16>;
	using h160 = FixedSizedByteArray<20>;
	using h256 = FixedSizedByteArray<32>;
	using h384 = FixedSizedByteArray<48>;
	using h512 = FixedSizedByteArray<64>;
	using h520 = FixedSizedByteArray<65>;
	using h1024 = FixedSizedByteArray<128>;


}


#endif /* SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_CRYPTO_BYTE_ARRAY_HPP_ */
