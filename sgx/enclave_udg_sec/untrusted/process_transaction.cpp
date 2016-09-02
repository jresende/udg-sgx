///*
// * process_transaction.cpp
// *
// *  Created on: Sep 1, 2016
// *      Author: nsamson
// */
//
//#include <sgx_eid.h>
//#include "udg.h"
//#include "udg_sec_u.h"
//#include <stdexcept>
//#include <sstream>
//#include <cinttypes>
//#include <cstdlib>
//#include <iostream>
//#include <Poco/Net/HTTPClientSession.h>
//#include <Poco/Net/HTTPRequest.h>
//#include <Poco/Net/HTTPResponse.h>
//#include <Poco/StreamCopier.h>
//#include <Poco/Path.h>
//#include <Poco/URI.h>
//#include <Poco/Exception.h>
//
//using namespace Poco::Net;
//using namespace Poco;
//
//int process_transaction(const char* block, const char* proof, const char* transaction_hash) {
//	int ecall_return;
//	int ret = ecall_udg_process(global_eid, &ecall_return, block, proof, transaction_hash);
//	return ecall_return;
//}
//
//struct BlockAndProof {
//	std::string block;
//	std::string proof;
//};
//
//BlockAndProof get_block_and_proof(uint64_t block_number, const char* transaction_hash) {
//
//	HTTPClientSession session("127.0.0.1", 8545);
//
//	HTTPRequest breq(HTTPRequest::HTTP_POST, "/", HTTPMessage::HTTP_1_1);
//	HTTPRequest preq(HTTPRequest::HTTP_POST, "/", HTTPMessage::HTTP_1_1);
//
//	session.sendRequest(breq) << "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBlockRlp\",\"params\":[\""
//			<< transaction_hash << "\"],\"id\":1}";
//	std::cout << breq.getURI() << "\n";
//
//	HTTPResponse bresp, presp;
//
//	session.receiveResponse(bresp);
//
//	session.sendRequest(preq) << "{\"jsonrpc\":\"2.0\",\"method\":\"eth_proof\",\"params\":[\""
//			<< transaction_hash << "\"],\"id\":1}";
//	std::cout << preq.getURI() << "\n";
//
//	session.receiveResponse(presp);
//
//
//}
//
//void verify_transaction(uint64_t block_number, const char* transaction_hash) {
//	auto bnp = get_block_and_proof(transaction_hash);
//	(void) process_transaction(bnp.block.c_str(), bnp.proof.c_str(), transaction_hash);
//}
