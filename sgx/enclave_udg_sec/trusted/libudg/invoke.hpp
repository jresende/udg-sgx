//
// Created by nsamson on 7/3/16.
//

#ifndef UDG_ARGUMENT_DEMANGLER_HPP
#define UDG_ARGUMENT_DEMANGLER_HPP

#include <string>
#include <stdint.h>
#include <vector>
#include <algorithm>
#include "intconv.hpp"
#include "BigInt.hpp"

namespace udg {

    const std::string left_str_delimiter = "STR_START_LEFT";
    const std::string right_str_delimiter = "STR_END_RIGHT";
    const std::string arg_delimiter = "||||";

    /**
     * Native method invocation input format
     * <method_name>(<type_list>)|arg0|arg1
     */

    namespace types {
        enum ArgType {
            UINT64,
            INT64,
            BYTES
        };
    }

    std::string unparse_arg(const uint64_t&);
    std::string unparse_arg(const int64_t&);
    std::string unparse_arg(const std::string&);

    class InvocationResult {
        std::vector<types::ArgType> output_types;
        std::vector<std::string> results;

    public:
        template <typename T>
        InvocationResult& with_result(const T& num);

        int parse_arg_str(const std::string& invoke_str);

        std::string to_string() const;
    };

    class NativeInvocation;

    typedef InvocationResult (*function_t)(const NativeInvocation&);

    class NativeMethod {
        std::string method_name;
        std::vector<types::ArgType> input_types;
        function_t fn;

        void operator() (types::ArgType type);

    public:

        NativeMethod(const std::string& method_name, function_t method);

        std::vector<types::ArgType>::const_iterator arg_type_begin() const;
        std::vector<types::ArgType>::const_iterator arg_type_end() const;

        void add_type(types::ArgType type);

        template <typename InputIterator>
        void add_types(InputIterator begin, InputIterator end) {
            std::for_each(begin, end, *this);
        }


        InvocationResult invoke(const NativeInvocation& args);
    };

    class NativeInvocationBuilder {
        std::string method_name;
        std::vector<types::ArgType> input_types;
        std::vector<std::string> arguments;

    public:
        NativeInvocationBuilder(const std::string& method_name);
        NativeInvocationBuilder& with_int64(const int64_t&);
        NativeInvocationBuilder& with_uint64(const uint64_t&);
        NativeInvocationBuilder& with_str(const std::string&);

        NativeInvocation build();
    };

    class NativeInvocation {
        std::string method_name;
        std::vector<types::ArgType> input_types;
        std::vector<std::string> arguments;

        friend class NativeInvocationBuilder;

    public:
        int parse_arg_str(const std::string& invoke_str);

        bool matches_type(const NativeMethod& decl) const;

        std::string to_string() const;

        std::vector<types::ArgType>::const_iterator types_begin() const;
        std::vector<types::ArgType>::const_iterator types_end() const;

        std::vector<std::string>::const_iterator args_begin() const;
        std::vector<std::string>::const_iterator args_end();
    };

    std::string to_string(const types::ArgType&);

    uint64_t parse_uint64(const std::string& arg);
    int64_t parse_int64(const std::string& arg);
    std::string parse_str(const std::string& arg);

    template <typename OutputIterator>
    int parse_invoke_type_list(const std::string& list, OutputIterator dest) {
        size_t prev_start = 0;
        size_t current_delim = list.find(",");

        if (list.compare("") == 0) {
            return 0;
        }

        while (prev_start != std::string::npos) {
            std::string type_name = list.substr(prev_start, current_delim - prev_start);

            if (type_name.compare("uint64") == 0) {
                *dest = types::UINT64;
            } else if (type_name.compare("int64") == 0) {
                *dest = types::INT64;
            } else if (type_name.compare("bytes") == 0) {
                *dest = types::BYTES;
            } else {
                return -1;
            }

            if (std::string::npos == current_delim) {
                break;
            }

            prev_start = current_delim + 1;
            current_delim = list.find(',', current_delim + 1);
            ++dest;
        }

        return 0;
    }
}

#endif //UDG_ARGUMENT_DEMANGLER_HPP
