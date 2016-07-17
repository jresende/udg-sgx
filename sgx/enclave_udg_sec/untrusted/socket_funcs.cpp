/*
 * socket_funcs.cpp
 *
 *  Created on: Jul 15, 2016
 *      Author: nsamson
 */

#include "udg_sec_u.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>

static int get_tcp_socket() {
    return socket(AF_INET, SOCK_STREAM, 0);
}

static int get_udp_socket() {
    return socket(AF_INET, SOCK_DGRAM, 0);
}

template <typename T>
T byte_swap(T data) {
	T out;

	uint8_t* out_ptr = reinterpret_cast<uint8_t*>(&out);
	uint8_t* in_ptr = reinterpret_cast<uint8_t*>(&data);

	for (size_t i = 0; i < sizeof(T); i++) {
		out_ptr[i] = in_ptr[sizeof(T) - 1 - i];
	}

	return out;
}

//the bytes are assigned in left-to-right order to produce the binary address
static int connect_socket(int fd, uint32_t addr, uint16_t port) {
    sockaddr_in inet_addr;
    inet_addr.sin_addr.s_addr = addr;
    inet_addr.sin_family = AF_INET;
    inet_addr.sin_port = byte_swap<uint16_t>(port);
    return connect(fd, (const sockaddr *) &inet_addr, sizeof(sockaddr_in));
}

static ssize_t sgx_send(int sock_fd, const void* buf, size_t len, int flags) {
    return send(sock_fd, buf, len, flags);
}

static ssize_t sgx_recv(int sock_fd, void* buf, size_t len, int flags) {
    return recv(sock_fd, buf, len, flags);
}

static int sgx_shutdown(int sockfd, int how) {
    return shutdown(sockfd, how);
}

/*
 * void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_tcp_socket, (int* sock));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_udp_socket, (int* sock));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_connect_socket, (int* res, int fd, uint32_t addr, uint16_t port));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_send, (ssize_t* res, const void* buf, size_t len, int flags));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_recv, (ssize_t* res, int sockfd, void* buf, size_t len, int flags));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_shutdown, (int* res, int sockfd, int how));
 */

void ocall_tcp_socket(int* sock) {
	*sock = get_tcp_socket();
}

void ocall_udp_socket(int* sock) {
	*sock = get_udp_socket();
}

void ocall_connect_socket(int* res, int fd, uint32_t addr, uint16_t port) {
	*res = connect_socket(fd, addr, port);
}

void ocall_send(ssize_t* res, int sock, const void* buf, size_t len, int flags) {
	*res = sgx_send(sock, buf, len, flags);
}

void ocall_recv(ssize_t* res, int sockfd, void* buf, size_t len, int flags) {
	*res = sgx_recv(sockfd, buf, len, flags);
}

void ocall_shutdown(int* res, int sockfd, int how) {
	*res = sgx_shutdown(sockfd, how);
}



