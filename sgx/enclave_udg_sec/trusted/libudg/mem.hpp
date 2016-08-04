/*
 * mem.hpp
 *
 *  Created on: Aug 2, 2016
 *      Author: nsamson
 */

#ifndef SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_MEM_HPP_
#define SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_MEM_HPP_

namespace udg {

	// Homebrew shared pointer implementation
	template <typename T>
	class shared_ptr {
		T* _data;
		uint32_t* ref_cnt;

		void dec() {
			*ref_cnt -= 1;

			if (ref_cnt == 0) {
				if (this->_data != nullptr) {
					delete this->_data;
				}
				delete ref_cnt;
			}
		}
	public:

		shared_ptr(T* d) {
			this->_data = d;
			ref_cnt = new uint32_t;
			*ref_cnt = 1;
		}
		shared_ptr() {
			this->_data = nullptr;
			ref_cnt = new uint32_t;
			*ref_cnt = 1;
		}
		shared_ptr(const shared_ptr& that) {
			this->_data = that._data;
			ref_cnt = that.ref_cnt;
			*ref_cnt += 1;
		}


		~shared_ptr() {
			this->dec();
		}

		void reset(T* new_dat) {
			this->dec();
			ref_cnt = new uint32_t;
			*ref_cnt = 1;
			this->_data = new_dat;
		}
		void reset() {
			this->dec();
			ref_cnt = new uint32_t;
			*ref_cnt = 1;
		}

		T* operator->() {
			return this->_data;
		}

		T& operator* () {
			return *(this->_data);
		}

		T* get() {
			return this->_data;
		}

		shared_ptr& operator=(shared_ptr that) {
			this->swap(that);
			return *this;
		}

		bool unique() const {
			return *ref_cnt == 1;
		}

		operator bool() const {
			return this->_data != nullptr;
		}

		uint32_t use_count() const {
			return *ref_cnt;
		}

		void swap(shared_ptr& that) {
			std::swap(this->_data, that._data);
			std::swap(this->ref_cnt, that.ref_cnt);
		}

		bool operator==(const shared_ptr& that) const {
			return this->_data == that._data;
		}
		bool operator!=(const shared_ptr& that) const {
			return !(*this == that);
		}
		bool operator>=(const shared_ptr& that) const {
			return this->_data >= that._data;
		}

		bool operator<=(const shared_ptr& that) const {
			return this->_data <= that._data;
		}
		bool operator>(const shared_ptr& that) const {
			return !(*this <= that);
		}
		bool operator<(const shared_ptr& that) const {
			return !(*this >= that);
		}

	};
}

#endif /* SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_MEM_HPP_ */
