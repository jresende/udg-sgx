///*
// * python_module.cpp
// *
// *  Created on: Sep 1, 2016
// *      Author: nsamson
// */
//
//#include <boost/python.hpp>
//#include <sgx_eid.h>
//#include "udg.h"
//#include <boost/shared_ptr.hpp>
//#include <stdexcept>
//#include <sgx_urts.h>
//
//using namespace boost::python;
//
//struct PythonHandler {
//	boost::shared_ptr<sgx_enclave_id_t> eid;
//
//	PythonHandler() {
//		int res = initialize_enclave();
//		if (res != 0) {
//			throw std::runtime_error("Could not initialize enclave");
//		}
//
//		auto id = new sgx_enclave_id_t;
//		*id = global_eid;
//		this->eid = boost::shared_ptr<sgx_enclave_id_t>(id, [](sgx_enclave_id_t* d) -> void {sgx_destroy_enclave(*d);});
//	}
//};
//
//#ifdef UDG_PYMODULE
//
//int process_transaction(std::string block, std::string proof, std::string transaction_hash) {
//
//}
//
//PythonHandler h;
//
//
//
//BOOST_PYTHON_MODULE(pyudg) {
//
//	def("process_transaction", )
//
//}
//
//#endif
