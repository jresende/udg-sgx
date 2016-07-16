/*
 * hex_encode.cpp
 *
 *  Created on: Jul 16, 2016
 *      Author: nsamson
 */

#include "hex_encode.hpp"

#include <string.h>
#include <cstdio>

std::string udg::hex_encode(const std::string& src) {
	std::string out = "0x";

	for (std::string::const_iterator it = src.begin();
			it != src.end();
			++it) {
		char hex[3] = {};
		snprintf(hex, 3, "%02x", (unsigned int) *it);
		out.append(hex);
	}

	return out;
}

std::string udg::hex_encode(const uint8_t* src, size_t len) {
	std::string out = "0x";

	for (const uint8_t* it = src;
		 it != src + len;
		 ++it) {
		char hex[3] = {};
		snprintf(hex, 3, "%02x", (unsigned int) *it);
		out.append(hex);
	}

	return out;
}


