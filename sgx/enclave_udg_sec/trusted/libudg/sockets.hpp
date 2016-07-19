//
// Created by nsamson on 7/15/16.
//

#ifndef UDG_SOCKETS_HPP
#define UDG_SOCKETS_HPP

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string>

namespace udg {

    struct ManagedFileDescriptor {
        uint64_t ref_cnt;
        int fd;

        ManagedFileDescriptor() : ref_cnt(0), fd(0) {}
    };

    class SocketConnection {
        ManagedFileDescriptor* fd;

        void swap(SocketConnection& that);

    public:
        SocketConnection(uint32_t inet_addr, uint16_t port, bool tcp=true);
        ssize_t send(const void *buf, size_t len, int flags);
        ssize_t recv(void *buf, size_t len, int flags);
        int shutdown(int how);

        ~SocketConnection();
        SocketConnection(const SocketConnection& that);
        SocketConnection& operator=(SocketConnection that);

    };

    uint32_t ip_addr_str_to_int(const char* addr, size_t len);
    uint32_t ip_addr_str_to_int(const std::string& str);

    uint32_t get_ip(); /// ... how do we do this securely?

}

#endif //UDG_SOCKETS_HPP
