//
// Created by nsamson on 7/4/16.
//


#include "invoke.hpp"
#include <iterator>

using namespace udg;

udg::NativeMethod::NativeMethod(const std::string &method_name, function_t method) : method_name(method_name) {
    this->fn = method;
}

std::vector<types::ArgType>::const_iterator udg::NativeMethod::arg_type_begin() const {
    return this->input_types.begin();
}

std::vector<types::ArgType>::const_iterator udg::NativeMethod::arg_type_end() const {
    return this->input_types.end();
}

void udg::NativeMethod::add_type(types::ArgType type) {
    this->input_types.push_back(type);
}

void udg::NativeMethod::operator()(types::ArgType type) {
    this->add_type(type);
}

InvocationResult udg::NativeMethod::invoke(const NativeInvocation &args) {
    return this->fn(args);
}

#if 0

void udg::InvocationResult::add_result(const uint64_t &num) {
    this->output_types.push_back(types::UINT64);
    this->results.push_back(udg::unparse_arg(num));
}

void udg::InvocationResult::add_result(const int64_t &num) {
    this->output_types.push_back(types::INT64);
    this->results.push_back(udg::unparse_arg(num));
}

void udg::InvocationResult::add_result(const std::string &bytes) {
    this->output_types.push_back(types::BYTES);
    this->results.push_back(udg::unparse_arg(bytes));
}
#else
namespace udg {
    template<>
    InvocationResult& InvocationResult::with_result<uint64_t>(const uint64_t &num) {
        this->output_types.push_back(types::UINT64);
        this->results.push_back(udg::unparse_arg(num));

        return *this;
    }

    template<>
    InvocationResult& InvocationResult::with_result<int64_t>(const int64_t &num) {
        this->output_types.push_back(types::INT64);
        this->results.push_back(udg::unparse_arg(num));

        return *this;
    }

    template<>
    InvocationResult& InvocationResult::with_result<std::string>(const std::string &bytes) {
        this->output_types.push_back(types::BYTES);
        this->results.push_back(udg::unparse_arg(bytes));

        return *this;
    }
}
#endif


std::string InvocationResult::to_string() const {
    std::string out;

    out.append("(");

    for (std::vector<types::ArgType>::const_iterator it = this->output_types.begin();
            it != this->output_types.end();
            ++it) {
        out.append(udg::to_string(*it));

        if (it + 1 != this->output_types.end()) {
            out.append(",");
        }
    }

    out.append(")");
    out.append(arg_delimiter);

    for (std::vector<std::string>::const_iterator it = this->results.begin();
         it != this->results.end();
         ++it) {
        out.append(*it);

        if (it + 1 != this->results.end()) {
            out.append(arg_delimiter);
        }
    }

    return out;
}

int InvocationResult::parse_arg_str(const std::string &invoke_str) {
    size_t method_name_end = invoke_str.find("(");

    if (method_name_end == std::string::npos) {
        return -1;
    }

    size_t type_list_end = invoke_str.find(")", method_name_end);

    if (type_list_end == std::string::npos) {
        return -2;
    }

    std::back_insert_iterator<std::vector<types::ArgType> > biterator(this->output_types);

    std::string type_list = invoke_str.substr(method_name_end + 1, type_list_end - (method_name_end + 1));

    int res = parse_invoke_type_list(type_list, biterator);

    if (res != 0) {
        return -3;
    }

    // Argument list is separated by arg_delimiter

    size_t first_bar = invoke_str.find(arg_delimiter);

    if (first_bar < type_list_end || first_bar == std::string::npos) {
        return -4;
    }

    while (first_bar != std::string::npos) {
        size_t next_bar = invoke_str.find(arg_delimiter, first_bar + 1);

        this->results.push_back(invoke_str.substr(first_bar + 1, (next_bar - (first_bar + 1))));

        first_bar = next_bar;
    }

    if (this->results.size() != this->results.size()) {
        return -5;
    }

    return 0;
}


bool udg::NativeInvocation::matches_type(const udg::NativeMethod &decl) const {
    return std::distance(decl.arg_type_begin(), decl.arg_type_end()) ==
           std::distance(this->input_types.begin(), this->input_types.begin())
                   && std::equal(decl.arg_type_begin(), decl.arg_type_end(), this->input_types.begin());
}

std::string udg::to_string(const types::ArgType & arg) {
    switch (arg) {
        case types::BYTES:
            return "bytes";

        case types::INT64:
            return "int64";

        case types::UINT64:
            return "uint64";
    }

    std::abort();
}

int udg::NativeInvocation::parse_arg_str(const std::string &invoke_str) {

    size_t method_name_end = invoke_str.find("(");

    if (method_name_end == std::string::npos) {
        return -1;
    }

    this->method_name = invoke_str.substr(0, method_name_end);

    size_t type_list_end = invoke_str.find(")", method_name_end);

    if (type_list_end == std::string::npos) {
        return -2;
    }

    std::back_insert_iterator<std::vector<types::ArgType> > biterator(this->input_types);

    std::string type_list = invoke_str.substr(method_name_end + 1, type_list_end - (method_name_end + 1));

    int res = parse_invoke_type_list(type_list, biterator);

    if (res != 0) {
        return -3;
    }

    // Argument list is separated by arg_delimiter

    size_t first_bar = invoke_str.find(arg_delimiter);

    if (first_bar < type_list_end || first_bar == std::string::npos) {
        return -4;
    }

    while (first_bar != std::string::npos) {
        size_t next_bar = invoke_str.find(arg_delimiter, first_bar + 1);

        this->arguments.push_back(invoke_str.substr(first_bar + 1, (next_bar - (first_bar + 1))));

        first_bar = next_bar;
    }

    if (this->arguments.size() != this->input_types.size()) {
        return -5;
    }

    return 0;
}

std::string NativeInvocation::to_string() const {
    std::string out;

    out.append(this->method_name);
    out.append("(");

    for (std::vector<types::ArgType>::const_iterator it = this->input_types.begin();
            it != this->input_types.end();
            ++it) {
        out.append(udg::to_string(*it));

        if (it + 1 != this->input_types.end()) {
            out.append(",");
        }
    }

    out.append(")");
    out.append(arg_delimiter);

    for (std::vector<std::string>::const_iterator it = this->arguments.begin();
            it != this->arguments.end();
            ++it) {
        out.append(*it);

        if (it + 1 != this->arguments.end()) {
            out.append(arg_delimiter);
        }
    }

    return out;
}

std::vector<types::ArgType>::const_iterator NativeInvocation::types_begin() const {
    return this->input_types.begin();
}

std::vector<types::ArgType>::const_iterator NativeInvocation::types_end() const {
    return this->input_types.end();
}

std::vector<std::string>::const_iterator NativeInvocation::args_begin() const {
    return this->arguments.begin();
}

std::vector<std::string>::const_iterator NativeInvocation::args_end() {
    return this->arguments.end();
}


std::string udg::unparse_arg(const uint64_t& inp) {
    return udg::ulltostr(inp);
}

std::string udg::unparse_arg(const int64_t& inp) {
    return udg::lltostr(inp);
}

std::string udg::unparse_arg(const std::string & inp) {
    return std::string(left_str_delimiter).append(inp).append(right_str_delimiter);
}


// Arg string is delimited by [[<arg_str>]]
std::string udg::parse_str(const std::string& arg) {
    // Find indexes of beginning and end.
    size_t beginning = arg.find(left_str_delimiter);

    if (beginning == std::string::npos) {
        return std::string(left_str_delimiter).append("ERR").append(right_str_delimiter);
    }

    size_t end = arg.find(right_str_delimiter);

    if (end == std::string::npos) {
        return std::string(left_str_delimiter).append("ERR").append(right_str_delimiter);
    }

    if (end < beginning) {
        return std::string(left_str_delimiter).append("ERR").append(right_str_delimiter);
    }

    return arg.substr(beginning + 2, (end - (beginning + 2)));

}

int64_t udg::parse_int64(const std::string& arg) {
    return udg::strtoll(arg.c_str(), NULL, 10);
}

uint64_t udg::parse_uint64(const std::string& arg) {
    return udg::strtoull(arg.c_str(), NULL, 10);
}

NativeInvocationBuilder::NativeInvocationBuilder(const std::string &method_name) {
    this->method_name = method_name;
}

NativeInvocationBuilder &NativeInvocationBuilder::with_int64(const int64_t & inp) {
    this->input_types.push_back(types::INT64);
    this->arguments.push_back(udg::unparse_arg(inp));

    return *this;
}

NativeInvocationBuilder &NativeInvocationBuilder::with_uint64(const uint64_t &inp) {
    this->input_types.push_back(types::UINT64);
    this->arguments.push_back(udg::unparse_arg(inp));

    return *this;
}

NativeInvocationBuilder &NativeInvocationBuilder::with_str(const std::string &inp) {
    this->input_types.push_back(types::BYTES);
    this->arguments.push_back(udg::unparse_arg(inp));

    return *this;
}

NativeInvocation NativeInvocationBuilder::build() {
    NativeInvocation out;
    out.arguments = this->arguments;
    out.input_types = this->input_types;
    out.method_name = this->method_name;

    return out;
}











