//
// Created by nsamson on 7/15/16.
//

#include "sockets.hpp"
#include "intconv.hpp"
#include <algorithm>

int get_tcp_socket();
int get_udp_socket();
int connect_socket(int fd, uint32_t addr, uint16_t port);
ssize_t sgx_send(int sockfd, const void *buf, size_t len, int flags);
ssize_t sgx_recv(int sockfd, void *buf, size_t len, int flags);
int sgx_shutdown(int sockfd, int how);

#ifdef NO_INTEL_SGX

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

int get_tcp_socket() {
    return socket(AF_INET, SOCK_STREAM, 0);
}

int get_udp_socket() {
    return socket(AF_INET, SOCK_DGRAM, 0);
}

int connect_socket(int fd, uint32_t addr, uint16_t port) {
    sockaddr_in inet_addr;
    inet_addr.sin_addr.s_addr = addr;
    inet_addr.sin_family = AF_INET;
    inet_addr.sin_port = udg::byte_swap<uint16_t>(port);
    return connect(fd, (const sockaddr *) &inet_addr, sizeof(sockaddr_in));
}

ssize_t sgx_send(int sock_fd, const void* buf, size_t len, int flags) {
    return send(sock_fd, buf, len, flags);
}

ssize_t sgx_recv(int sock_fd, void* buf, size_t len, int flags) {
    return recv(sock_fd, buf, len, flags);
}

int sgx_shutdown(int sockfd, int how) {
    return shutdown(sockfd, how);
}

#else

#include "../udg_sec_t.h"

int get_tcp_socket() {
	int res;
	ocall_tcp_socket(&res);
	return res;
}

int get_udp_socket() {
	int res;
	ocall_udp_socket(&res);
	return res;
}

int connect_socket(int fd, uint32_t addr, uint16_t port) {
	int res;
	ocall_connect_socket(&res, fd, addr, port);
	return res;
}

ssize_t sgx_send(int sock_fd, const void* buf, size_t len, int flags) {
	long ret;
    ocall_send(&ret, sock_fd, buf, len, flags);
    return (ssize_t) ret;
}

ssize_t sgx_recv(int sock_fd, void* buf, size_t len, int flags) {
	long ret;
	ocall_recv(&ret, sock_fd, buf, len, flags);
	return (ssize_t) ret;
}

int sgx_shutdown(int sockfd, int how) {
	int res;
    ocall_shutdown(&res, sockfd, how);
    return res;
}


#endif

udg::SocketConnection::SocketConnection(uint32_t inet_addr, uint16_t port, bool tcp) {

    int sock;

    if (tcp) {
        sock = get_tcp_socket();

        if (sock < 1) {
            throw sock;
        }
    } else {
        sock = get_udp_socket();

        if (sock < 1) {
            throw sock;
        }
    }

    int conn_stat = connect_socket(sock, inet_addr, port);

    if (conn_stat < 0) {
        throw conn_stat;
    }

    this->fd = new ManagedFileDescriptor();
    this->fd->ref_cnt++;
    this->fd->fd = sock;

}

udg::SocketConnection::~SocketConnection() {
    this->fd->ref_cnt--;

    if (this->fd->ref_cnt == 0) {
        (void) this->shutdown(2); // SHUT_RDWR
        delete this->fd;
    }
}

ssize_t udg::SocketConnection::send(const void *buf, size_t len, int flags) {
    return sgx_send(this->fd->fd, buf, len, flags);
}

ssize_t udg::SocketConnection::recv(void *buf, size_t len, int flags) {
    return sgx_recv(this->fd->fd, buf, len, flags);
}

int udg::SocketConnection::shutdown(int how) {
    return sgx_shutdown(this->fd->fd, how);
}

udg::SocketConnection::SocketConnection(const SocketConnection &that) {
    this->fd = that.fd;
    this->fd->ref_cnt++;
}

udg::SocketConnection& udg::SocketConnection::operator=(SocketConnection that) {
    this->swap(that);
    return *this;
}

void udg::SocketConnection::swap(SocketConnection &that) {
    std::swap(this->fd, that.fd);
}























