//
// Created by nsamson on 7/10/16.
//

#ifndef UDG_JSON_HPP
#define UDG_JSON_HPP

#include <string>

namespace udg {
    namespace json {
        class JSONValue {
            union Contents {
                std::string str;
                
            };
        };


    }
}

#endif //UDG_JSON_HPP
