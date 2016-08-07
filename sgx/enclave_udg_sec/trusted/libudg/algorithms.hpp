/*
 * algorithms.hpp
 *
 *  Created on: Aug 7, 2016
 *      Author: nsamson
 */

#ifndef SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_ALGORITHMS_HPP_
#define SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_ALGORITHMS_HPP_

namespace udg {

	template <typename InputIterator, typename UnaryPredicate>
	bool all_match(InputIterator b, InputIterator e, UnaryPredicate p) {
		for (; b != e; ++b) {
			if (!p(*b)) {
				return false;
			}
		}

		return true;
	}

	template <typename InputIterator, typename UnaryPredicate>
	bool any_match(InputIterator b, InputIterator e, UnaryPredicate p) {
		for (; b != e; ++b) {
			if (p(*b)) {
				return true;
			}
		}

		return false;
	}

}



#endif /* SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_ALGORITHMS_HPP_ */
