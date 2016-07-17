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

std::vector<uint8_t> udg::hex_decode(const std::string& src) {
	std::vector<uint8_t> out;

	std::string cpy(src);

	if (cpy.substr(0, 2).compare("0x") == 0) {
		cpy = cpy.substr(2);
	}

	if (cpy.length() % 2 != 0) {
		cpy.insert(cpy.begin(), '0');
	}

	for (size_t i = 0; i < cpy.length(); i += 2) {
		char sub[3] = {};
		sub[0] = cpy.at(i);
		sub[1] = cpy.at(i + 1);

		out.push_back((uint8_t) (0xFF & strtol(sub, nullptr, 16)));
	}

	return out;
}
