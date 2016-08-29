/*
 * invoke.hpp
 *
 *  Created on: Aug 29, 2016
 *      Author: nsamson
 */

#ifndef SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_INVOKE_HPP_
#define SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_INVOKE_HPP_

#include "ethereum/blockchain.hpp"
#include "ethereum/rlp.hpp"

namespace udg {
	namespace invoke {
		rlp::rlpvec process_transactions(const std::vector<eth::Transaction>& transactions);
	}
}


#endif /* SGX_ENCLAVE_UDG_SEC_TRUSTED_LIBUDG_INVOKE_HPP_ */
