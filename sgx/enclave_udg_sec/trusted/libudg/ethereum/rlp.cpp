//
// Created by nsamson on 6/29/16.
//

#include "rlp.hpp"
#include <algorithm>
#include <iterator>
#include "../hex_encode.hpp"

using namespace udg::rlp;

uint8_t min_byte_rep(uint64_t size) {
    uint64_t masks[] = {
            0xFFULL,
            0xFFFFULL,
            0xFFFFFFULL,
            0xFFFFFFFFULL,
            0xFFFFFFFFFFULL,
            0xFFFFFFFFFFFFULL,
            0xFFFFFFFFFFFFFFULL,
            0xFFFFFFFFFFFFFFFFULL,
            0
    };

    for (uint8_t i = 0; masks[i] != 0; i++) {
        uint64_t mask = masks[i];
        if ((mask & size) == size) {
            return (uint8_t) (i + 1);
        }
    }

    return sizeof(uint64_t);

}

uint8_t udg::rlp::bytes_needed(uint64_t o) {
	return min_byte_rep(o);
}

rlpvec udg::rlp::to_rlp(char data_in) {

    rlpvec out;

    unsigned char data = (unsigned char) (data_in);

    if (data < 128) {
        out.push_back(data);
    } else {
        out.push_back(129);
        out.push_back(data);
    }

    return out;
}

rlpvec udg::rlp::to_rlp(std::string data) {
    return to_rlp(data.c_str(), data.size());
}

rlpvec udg::rlp::to_rlp(const char *data_in, size_t len) {

    rlpvec out;

    const uint8_t* data = reinterpret_cast<const uint8_t*>(data_in);

    if (len == 0) {
        out.push_back(128);
    } else if (len == 1 && data[0] <= 0x7f) {
        out.push_back(data[0]);
    } else if (len == 1 && data[0] > 0x7f) {
        out.push_back(129);
        out.push_back(data[0]);
    } else if (len <= 55) {
        out.push_back((const unsigned char &) (128 + len));
        std::copy(data, data + len, std::back_insert_iterator<rlpvec>(out));
    } else {
        out.push_back((const unsigned char &) (0xb7 + min_byte_rep(len)));
        uint64_t size = byte_swap<uint64_t>(len);
        uint8_t* size_ptr = reinterpret_cast<uint8_t*>(&size);

        uint8_t bytes_needed  = min_byte_rep(len);
        for (uint8_t i = sizeof(uint64_t) - (uint8_t) (bytes_needed); i < sizeof(uint64_t); i++) {
            out.push_back(size_ptr[i]);
        }

        std::copy(data, data + len, std::back_insert_iterator<rlpvec>(out));
    }

    return out;
}

std::string udg::rlp::to_string(const rlpvec &in) {
    return std::string(in.begin(), in.end());
}


ContentType RLPData::get_type() const {
    return this->type;
}

int RLPData::retrieve_bytes(rlpvec &out) const {
    switch (this->type) {

        case BYTE:
        case SMALL_STR:
        case LONG_STR: {
            out.clear();
            std::copy(this->bytes()->begin(),
                      this->bytes()->end(),
                      std::back_insert_iterator<rlpvec>(out));
        }
            return 0;


        case SMALL_ARR:
        case LONG_ARR:
            return -1;
    }
    return -2;
}

int RLPData::retrieve_arr(std::vector<RLPData> &out) const {
    switch (this->type) {

        case BYTE:
        case SMALL_STR:
        case LONG_STR:
            return -1;

        case SMALL_ARR:
        case LONG_ARR:
            {
                out.clear();
                std::copy(this->arr()->begin(),
                          this->arr()->end(),
                          std::back_insert_iterator<std::vector<RLPData> >(out));
            }
            return 0;
    }
    return -2;
}

rlpvec *RLPData::bytes() const {
    return reinterpret_cast<rlpvec*>(this->_data);
}

rlpvec *RLPData::bytes() {
    return reinterpret_cast<rlpvec*>(this->_data);
}

std::vector<RLPData> *RLPData::arr() {
    return reinterpret_cast<std::vector<RLPData>*>(this->_data);
}

std::vector<RLPData> *RLPData::arr() const {
    return reinterpret_cast<std::vector<RLPData>*>(this->_data);
}

RLPData::~RLPData() {
    switch (this->type) {
        case BYTE:
        case SMALL_STR:
        case LONG_STR:
            delete this->bytes();
            break;

        case SMALL_ARR:
        case LONG_ARR:
            delete this->arr();
            break;
    }
}

std::string RLPData::to_string() const {
    std::string out = "";

    switch (this->type) {

        case BYTE:
        case SMALL_STR:
        case LONG_STR:
        {
            out.append("\"");
            out.append(std::string(this->bytes()->begin(), this->bytes()->end()));
            out.append("\"");
        }
            break;

        case SMALL_ARR:
        case LONG_ARR:
        {

            std::vector<RLPData>::const_iterator end = this->arr()->end();

            out.append("[");
            for (std::vector<RLPData>::const_iterator it = this->arr()->begin();
                 it != end;
                 ++it) {

                out.append(it->to_string());

                if (it + 1 != end) {
                    out.append(", ");
                }

            }
            out.append("]");
        }
            break;
    }

    return out;
}

std::string udg::rlp::RLPData::to_hex_string() const {
	std::string out = "";

	switch (this->type) {

		case BYTE:
		case SMALL_STR:
		case LONG_STR:
		{
			out.append(udg::hex_encode(&(*this->bytes())[0], this->bytes()->size()));
		}
			break;

		case SMALL_ARR:
		case LONG_ARR:
		{

			std::vector<RLPData>::const_iterator end = this->arr()->end();

			out.append("[");
			for (std::vector<RLPData>::const_iterator it = this->arr()->begin();
				 it != end;
				 ++it) {

				out.append(it->to_string());

				if (it + 1 != end) {
					out.append(", ");
				}

			}
			out.append("]");
		}
			break;
	}

	return out;
}

RLPData &RLPData::operator=(RLPData that) {

    swap(that);

    return *this;
}

void RLPData::swap(RLPData &other) {
    std::swap(this->_data, other._data);
    std::swap(this->type, other.type);
}

RLPData::RLPData(const RLPData &that) {
    this->type = that.type;

    switch (this->type) {
        case BYTE:
        case SMALL_STR:
        case LONG_STR:
        {
            this->_data = new rlpvec(*that.bytes());
        }
            break;

        case SMALL_ARR:
        case LONG_ARR:
        {
            this->_data = new std::vector<RLPData>(*that.arr());
        }
            break;
    }
}

rlpvec udg::rlp::to_rlp_list(const std::vector<rlpvec>& data) {
	size_t total_size = 0;

	rlpvec out;

	for (auto& rlpdat : data) {
		total_size += rlpdat.size();
	}

	if (total_size > 55) {
		out.push_back((const unsigned char &) (0xf7 + min_byte_rep(total_size)));
		uint64_t size = byte_swap<uint64_t>(total_size);
		uint8_t* size_ptr = reinterpret_cast<uint8_t*>(&size);

		uint8_t bytes_needed  = min_byte_rep(total_size);
		for (uint8_t i = sizeof(uint64_t) - (uint8_t) (bytes_needed); i < sizeof(uint64_t); i++) {
			out.push_back(size_ptr[i]);
		}

		for (auto& rlpdat : data) {
			out.insert(out.end(), rlpdat.begin(), rlpdat.end());
		}
	} else {
		out.push_back((char) 0xc0 + (char) total_size);
		for (auto& rlpdat : data) {
			out.insert(out.end(), rlpdat.begin(), rlpdat.end());
		}
	}

	return out;
}

rlpvec udg::rlp::to_rlp(const std::vector<uint8_t>& buf) {
	return to_rlp(buf.begin(), buf.end());
}





















