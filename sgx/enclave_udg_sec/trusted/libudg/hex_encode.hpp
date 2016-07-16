//
// Created by nsamson on 7/5/16.
//

#ifndef UDG_HEXENCODE_HPP
#define UDG_HEXENCODE_HPP

#include <string>
#include <stdint.h>


namespace udg {
	std::string hex_encode(const std::string& src);

	std::string hex_encode(const uint8_t* src, size_t len);
}

#endif //UDG_HEXENCODE_HPP
