//
// Created by nsamson on 6/29/16.
//

#ifndef EVMSGX_RLP_HPP
#define EVMSGX_RLP_HPP

#include <stdint.h>
#include <vector>
#include <string>
#include <algorithm>
#include <iterator>
#include "../intconv.hpp"

namespace udg {
    namespace rlp {
        enum ContentType {
            BYTE = 1,
            SMALL_STR, // 55 bytes or less
            LONG_STR, // Longer than 55 bytes
            SMALL_ARR, // Array length <= 55 bytes
            LONG_ARR // Array length > 55 bytes
        };

        constexpr bool is_arr(const ContentType& c) {
        	return c >= 4;
        }

        constexpr bool is_str(const ContentType& c) {
        	return c < 4;
        }

        const size_t BIGLEN = 55;

        typedef std::vector<uint8_t> rlpvec;
        typedef std::vector<rlpvec> rlplist;


        rlpvec to_rlp(char data);
        rlpvec to_rlp(std::string data);
        rlpvec to_rlp(const char* data, size_t len);

        std::string to_string(const rlpvec& in);

        uint8_t bytes_needed(uint64_t);

        template <typename InputIterator>
        rlpvec to_rlp(InputIterator begin, InputIterator end) {

            rlpvec out;

            for (; begin != end; ++begin) {
                rlpvec conv = to_rlp(*begin);

                std::copy(
                        conv.begin(),
                        conv.end(),
                        std::back_insert_iterator<rlpvec>(out)
                );
            }

            // need to calculate length data for rlp

            if (out.size() <= BIGLEN) {
                uint8_t first_byte = 192;
                first_byte += out.size();
                out.insert(out.begin(), first_byte);
            } else {
                uint8_t first_byte = 247;
                first_byte += bytes_needed(out.size());
                uint64_t big_endian_size = udg::byte_swap<uint64_t>(out.size());
                uint8_t* size_ptr = reinterpret_cast<uint8_t*>(&big_endian_size);

                uint8_t bn = bytes_needed(big_endian_size);

                out.insert(out.begin(), size_ptr + (sizeof(uint64_t) - bn), size_ptr + sizeof(uint64_t));
                out.insert(out.begin(), first_byte);
            }

            return out;
        }

        rlpvec to_rlp(const std::vector<uint8_t>& buf);

        rlpvec to_rlp_list(const rlplist& data);

        class RLPData {
            ContentType type;

            rlpvec* bytes() const;
            rlpvec* bytes();

            std::vector<RLPData>* arr();
            std::vector<RLPData>* arr() const;

            void* _data;

            void swap(RLPData& other);

        public:

            RLPData() {
                this->_data = NULL;
            };

            RLPData(const RLPData& that);
            RLPData& operator= (RLPData that);

            ContentType get_type() const;

            bool is_arr() const {
            	return this->type >= 4;
            }

            bool is_str() const {
            	return !this->is_arr();
            }

            int retrieve_bytes(rlpvec& out) const;
            int retrieve_arr(std::vector<RLPData>& out) const;

            template <typename RandomAccessIterator>
            long parse_bytes(RandomAccessIterator it, RandomAccessIterator end);

            std::string to_string() const;
            std::string to_hex_string() const;

            ~RLPData();
        };

        template <typename RandomAccessIterator>
        long RLPData::parse_bytes(RandomAccessIterator it, RandomAccessIterator end) {

            RandomAccessIterator start_it = it;

            if (((unsigned char)*it) < 0x80) {
                this->type = BYTE;
                this->_data = new rlpvec();
                this->bytes()->push_back(*it);
                it++;
            } else if (((unsigned char)*it) <= 0xb7) {
                this->type = SMALL_STR;
                this->_data = new rlpvec();

                uint64_t str_size = (uint64_t) (((unsigned char)*it) - 0x80);
                std::copy(it + 1, it + 1 + str_size, std::back_insert_iterator<rlpvec>(*this->bytes()));
                it += 1 + str_size;
            } else if (((unsigned char)*it) <= 0xbf) {
                this->type = LONG_STR;
                this->_data = new rlpvec();

                uint64_t be_size = 0;
                uint8_t* be_size_ptr = reinterpret_cast<uint8_t*>(&be_size);
                uint8_t size_size = (((unsigned char)*it) - 0xb7);

                if (std::distance(it + 1, it + 1 + (*it - 0xb7)) > 8) {
                    return -5;
                }

                it++;
                for (uint8_t index = sizeof(uint64_t) - size_size; index < sizeof(uint64_t); index++, ++it) {
                    be_size_ptr[index] = *it;
                }

                uint64_t le_size = udg::byte_swap<uint64_t>(be_size);

                std::copy(it, it + le_size,
                          std::back_insert_iterator<rlpvec>(*this->bytes()));
                it += le_size;
            } else if (((unsigned char)*it) <= 0xf7) {
                this->type = SMALL_ARR;
                this->_data = new std::vector<RLPData>();

                uint8_t size = (uint8_t) (((unsigned char)*it) - 0xc0);
                it++;
                RandomAccessIterator array_data_start = it;

                while (std::distance(array_data_start, it) < size) {
                    RLPData new_dat;
                    long bytes_read = new_dat.parse_bytes(it, end);
                    this->arr()->push_back(new_dat);
                    it += bytes_read;
                }
            } else {
                this->type = LONG_ARR;
                this->_data = new std::vector<RLPData>();

                uint64_t be_size = 0;
                uint8_t* be_size_ptr = reinterpret_cast<uint8_t*>(&be_size);
                uint8_t size_size = (((unsigned char)*it) - 0xf7);

                if (std::distance(it + 1, it + 1 + (((unsigned char)*it) - 0xf7)) > 8) {
                    return -5;
                }

                it++;
                for (uint8_t index = sizeof(uint64_t) - size_size; index < sizeof(uint64_t); index++, ++it) {
                    be_size_ptr[index] = *it;
                }

                uint64_t le_size = udg::byte_swap<uint64_t>(be_size);
                RandomAccessIterator array_data_start = it;

                while ((unsigned long) std::distance(array_data_start, it) < le_size) {
                    RLPData new_dat;
                    long bytes_read = new_dat.parse_bytes(it, end);
                    this->arr()->push_back(new_dat);
                    it += bytes_read;
                }
            }

            return std::distance(start_it, it);
        }

        typedef std::vector<RLPData> rlpdlist;
        std::vector<RLPData> decode_list(const rlpvec& ls);
        rlpvec decode_string(const rlpvec& str);

        struct RLPConvertable {
        	virtual rlpvec to_rlp() const;
        	virtual std::string to_rlp_str() const;
        	virtual ~RLPConvertable();
        };

    }
}

#endif //EVMSGX_RLP_HPP
