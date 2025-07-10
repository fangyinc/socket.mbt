#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdlib.h>
#include <signal.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#endif

#include "moonbit.h"
    
// The Raw File Descriptor type
#define RAW_FD int64_t

// Define some constants and types as Moonbit socket types.
// These constants are used to map Moonbit socket types to system socket types.
#define MOONBIT_DOMAIN_IPV4    2
#define MOONBIT_DOMAIN_IPV6    10
#define MOONBIT_DOMAIN_UNIX    1
#define MOONBIT_TYPE_STREAM    1
#define MOONBIT_TYPE_DGRAM     2
//SOCK_RAW
#define MOONBIT_TYPE_RAW      3
#define MOONBIT_PROTO_TCP      6
#define MOONBIT_PROTO_UDP      17
//ICMPV4
#define MOONBIT_PROTO_ICMPV4   1
#define MOONBIT_PROTO_ICMPV6   58
#define MOONBIT_SHUT_RD        0
#define MOONBIT_SHUT_WR        1
#define MOONBIT_SHUT_RDWR      2
#define MOONBIT_MSG_PEEK       0
#define MOONBIT_MSG_DONTWAIT   1
#define MOONBIT_SOCKOPT_REUSEADDR 0
#define MOONBIT_SOCKOPT_KEEPALIVE 1
#define MOONBIT_SOCKOPT_RCVBUF   2
#define MOONBIT_SOCKOPT_SNDBUF   3


typedef struct {
    struct sockaddr_storage addr;
    socklen_t addr_len;
} moonbit_sender_info;

static int map_domain(int moonbit_domain) {
    switch (moonbit_domain) {
        case MOONBIT_DOMAIN_IPV4: return AF_INET;
        case MOONBIT_DOMAIN_IPV6: return AF_INET6;
        case MOONBIT_DOMAIN_UNIX: return AF_UNIX;
        default: return AF_INET; // Default to IPv4
    }
}

static int map_type(int moonbit_type) {
    switch (moonbit_type) {
        case MOONBIT_TYPE_STREAM: return SOCK_STREAM;
        case MOONBIT_TYPE_DGRAM:  return SOCK_DGRAM;
        case MOONBIT_TYPE_RAW:    return SOCK_RAW;
        default: return SOCK_STREAM;
    }
}

static int map_protocol(int moonbit_proto) {
    switch (moonbit_proto) {
        case MOONBIT_PROTO_TCP: return IPPROTO_TCP;
        case MOONBIT_PROTO_UDP: return IPPROTO_UDP;
        case MOONBIT_PROTO_ICMPV4: return IPPROTO_ICMP;
        case MOONBIT_PROTO_ICMPV6: return IPPROTO_ICMPV6;
        default: return IPPROTO_IP; // For automatic protocol selection
    }
}

static int map_how(int moonbit_how) {
    switch (moonbit_how) {
        case MOONBIT_SHUT_RD:   return SHUT_RD;
        case MOONBIT_SHUT_WR:   return SHUT_WR;
        case MOONBIT_SHUT_RDWR: return SHUT_RDWR;
        default: return SHUT_RDWR;
    }
}

static int map_flags(int moonbit_flag) {
    int flags = 0;
    
    if (moonbit_flag & (1 << MOONBIT_MSG_PEEK)) {
#ifdef MSG_PEEK
        flags |= MSG_PEEK;
#endif
    }
    
    if (moonbit_flag & (1 << MOONBIT_MSG_DONTWAIT)) {
#ifdef MSG_DONTWAIT
        flags |= MSG_DONTWAIT;
#elif defined(O_NONBLOCK)
        // For systems without MSG_DONTWAIT, use non-blocking IO
        moonbit_socket_set_nonblocking(sockfd, 1);
#endif
    }
    
    return flags;
}

static void map_sockopt(int moonbit_opt, int* level, int* optname) {
    *level = SOL_SOCKET;
    
    switch (moonbit_opt) {
        case MOONBIT_SOCKOPT_REUSEADDR:
            *optname = SO_REUSEADDR;
            break;
        case MOONBIT_SOCKOPT_KEEPALIVE:
            *optname = SO_KEEPALIVE;
            break;
        case MOONBIT_SOCKOPT_RCVBUF:
            *optname = SO_RCVBUF;
            break;
        case MOONBIT_SOCKOPT_SNDBUF:
            *optname = SO_SNDBUF;
            break;
        default:
            *optname = SO_REUSEADDR;
    }
}


// Initialize winsock on Windows
MOONBIT_FFI_EXPORT int moonbit_socket_init(void) {
#ifdef _WIN32
    WSADATA wsa_data;
    return WSAStartup(MAKEWORD(2, 2), &wsa_data);
#else
    return 0;
#endif
}

// Cleanup winsock on Windows
MOONBIT_FFI_EXPORT void moonbit_socket_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

// Create socket
MOONBIT_FFI_EXPORT RAW_FD moonbit_socket_create(int moonbit_domain, int moonbit_type, int moonbit_protocol) {
    int domain = map_domain(moonbit_domain);
    int type = map_type(moonbit_type);
    int protocol = map_protocol(moonbit_protocol);
#ifdef _WIN32
    SOCKET s = socket(domain, type, protocol);
    if (s == INVALID_SOCKET) {
        WSACleanup();
        return -1;
    } else {
        return (RAW_FD)s;
    }
#else
    int s = socket(domain, type, protocol);
    return (s == -1) ? -1 : (RAW_FD)s;
#endif
}

// Close socket
MOONBIT_FFI_EXPORT int moonbit_socket_close(RAW_FD sockfd) {
#ifdef _WIN32
    SOCKET s = (SOCKET)sockfd;
    if (closesocket(s) == SOCKET_ERROR) {
        WSACleanup();
        return -1;
    } else {
        WSACleanup();
        return 0
    }
#else
    int s = (int)sockfd;
    return (close(s) == -1) ? -1 : 0;
#endif
}

MOONBIT_FFI_EXPORT int moonbit_socket_shutdown(RAW_FD sockfd, int moonbit_how) {
    int how = map_how(moonbit_how);
#ifdef _WIN32
    SOCKET s = (SOCKET)sockfd;
    return shutdown(s, how);
#else
    int s = (int)sockfd;
    return shutdown(s, how);
#endif
}

// Bind socket to address using separate parameters
MOONBIT_FFI_EXPORT int moonbit_socket_bind_ipv4(RAW_FD sockfd, moonbit_bytes_t ip, uint16_t port) {
#ifdef _WIN32
    SOCKET s = (SOCKET)sockfd;
#else
    int s = (int)sockfd;
#endif
    
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    
    // IP address handling
    if (ip != NULL && strlen((const char*)ip) > 0) {
        // support both dot-decimal and hexadecimal formats
        if (inet_pton(AF_INET, (const char*)ip, &sa.sin_addr) != 1) {
            return -1; // Invalid IP address format
        }
    } else {
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    
    int res = bind(s, (struct sockaddr*)&sa, sizeof(sa));
#ifdef _WIN32
    if (res == SOCKET_ERROR) {
        closesocket(s);
        WSACleanup()
        return -1;
    }
#endif
    return res;
}

MOONBIT_FFI_EXPORT int moonbit_socket_bind_ipv6(RAW_FD sockfd, moonbit_bytes_t ip, uint16_t port) {
#ifdef _WIN32
    SOCKET s = (SOCKET)sockfd;
#else
    int s = (int)sockfd;
#endif
    
    struct sockaddr_in6 sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons(port);
    
    if (ip && strlen((const char*)ip) > 0) {
        if (inet_pton(AF_INET6, (const char*)ip, &sa.sin6_addr) != 1) {
            return -1;
        }
    } else {
        sa.sin6_addr = in6addr_any;
    }
    
    int res = bind(s, (struct sockaddr*)&sa, sizeof(sa));

#ifdef _WIN32
    if (res == SOCKET_ERROR) {
        closesocket(s);
        WSACleanup();
        return -1;
    }
#endif
    return res;
}

// Connect to address using separate parameters
MOONBIT_FFI_EXPORT int moonbit_socket_connect_ipv4(RAW_FD sockfd, moonbit_bytes_t ip, uint16_t port) {
#ifdef _WIN32
    SOCKET s = (SOCKET)sockfd;
#else
    int s = (int)sockfd;
#endif
    
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    
    if (inet_aton((const char*)ip, &sa.sin_addr) != 1) {
        return -1;
    }
    
    int res = connect(s, (struct sockaddr*)&sa, sizeof(sa));
#ifdef _WIN32
    if (res == SOCKET_ERROR) {
        closesocket(s);
        WSACleanup();
        return -1;
    }
#endif
    return res;
}

MOONBIT_FFI_EXPORT int moonbit_socket_connect_ipv6(RAW_FD sockfd, moonbit_bytes_t ip, uint16_t port) {
#ifdef _WIN32
    SOCKET s = (SOCKET)sockfd;
#else
    int s = (int)sockfd;
#endif
    
    struct sockaddr_in6 sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons(port);
    
    if (inet_pton(AF_INET6, (const char*)ip, &sa.sin6_addr) != 1) {
        return -1;
    }
    
    int res = connect(s, (struct sockaddr*)&sa, sizeof(sa));
#ifdef _WIN32
    if (res == SOCKET_ERROR) {
        closesocket(s);
        WSACleanup();
        return -1;
    }
#endif
    return res;
}

// Listen for connections
MOONBIT_FFI_EXPORT int moonbit_socket_listen(RAW_FD sockfd, int backlog) {
#ifdef _WIN32
    SOCKET s = (SOCKET)sockfd;
#else
    int s = (int)sockfd;
#endif
    int res = listen(s, backlog);
    
#ifdef _WIN32
    if (res == SOCKET_ERROR) {
        closesocket(s);
        WSACleanup();
        return -1;
    }
#endif
    return res;
}

// Accept connection - returns client fd
MOONBIT_FFI_EXPORT RAW_FD moonbit_socket_accept(RAW_FD sockfd) {
    struct sockaddr_in peeraddr;
    socklen_t peerlen = sizeof(peeraddr);

#ifdef _WIN32
    SOCKET s = (SOCKET)sockfd;
    SOCKET client = accept(s, (struct sockaddr*)&peeraddr, &peerlen);
    return (client == INVALID_SOCKET) ? -1 : (RAW_FD)client;
#else
    int s = (int)sockfd;
    int client = accept(s, (struct sockaddr*)&peeraddr, &peerlen);
    return (client == -1) ? -1 : (RAW_FD)client;
#endif
}

// Get peer address info after accept
MOONBIT_FFI_EXPORT moonbit_bytes_t moonbit_socket_getpeer_ip(RAW_FD sockfd) {
#ifdef _WIN32
    SOCKET s = (SOCKET)sockfd;
#else
    int s = (int)sockfd;
#endif
    
    struct sockaddr_storage sa;
    socklen_t len = sizeof(sa);
    
    if (getpeername(s, (struct sockaddr*)&sa, &len) != 0) {
        return NULL;
    }
    
    char ip_str[INET6_ADDRSTRLEN];
    if (sa.ss_family == AF_INET) {
        struct sockaddr_in *sa4 = (struct sockaddr_in*)&sa;
        inet_ntop(AF_INET, &sa4->sin_addr, ip_str, INET_ADDRSTRLEN);
    } else if (sa.ss_family == AF_INET6) {
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6*)&sa;
        inet_ntop(AF_INET6, &sa6->sin6_addr, ip_str, INET6_ADDRSTRLEN);
    } else {
        return NULL;
    }
    
    int len_str = strlen(ip_str);
    moonbit_bytes_t result = moonbit_make_bytes(len_str, 0);
    if (result) memcpy(result, ip_str, len_str);
    return result;
}

MOONBIT_FFI_EXPORT uint16_t moonbit_socket_getpeer_port(RAW_FD sockfd) {
#ifdef _WIN32
    SOCKET s = (SOCKET)sockfd;
#else
    int s = (int)sockfd;
#endif
    
    struct sockaddr_storage sa;
    socklen_t len = sizeof(sa);
    
    if (getpeername(s, (struct sockaddr*)&sa, &len) != 0) {
        return 0;
    }
    
    if (sa.ss_family == AF_INET) {
        struct sockaddr_in *sa4 = (struct sockaddr_in*)&sa;
        return ntohs(sa4->sin_port);
    } else if (sa.ss_family == AF_INET6) {
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6*)&sa;
        return ntohs(sa6->sin6_port);
    }
    
    return 0;
}

// Send data
MOONBIT_FFI_EXPORT int moonbit_socket_send(RAW_FD sockfd, moonbit_bytes_t data, int len, int moonbit_flags) {
    int flags = map_flags(moonbit_flags);
#ifdef _WIN32
    SOCKET s = (SOCKET)sockfd;
    return send(s, (const char*)data, len, flags);
#else
    int s = (int)sockfd;
    return send(s, (const char*)data, len, flags);
#endif
}

// Receive data
MOONBIT_FFI_EXPORT int moonbit_socket_recv(RAW_FD sockfd, moonbit_bytes_t buffer, int len, int moonbit_flags) {
    int flags = map_flags(moonbit_flags);
#ifdef _WIN32
    SOCKET s = (SOCKET)sockfd;
    return recv(s, (char*)buffer, len, flags);
#else
    int s = (int)sockfd;
    return recv(s, (char*)buffer, len, flags);
#endif
}

// Send data to specific address (UDP) - IPv4
MOONBIT_FFI_EXPORT int moonbit_socket_sendto_ipv4(RAW_FD sockfd, moonbit_bytes_t data, int len, int moonbit_flags, 
                                                   moonbit_bytes_t ip, uint16_t port) {
    int flags = map_flags(moonbit_flags);
#ifdef _WIN32
    SOCKET s = (SOCKET)sockfd;
#else
    int s = (int)sockfd;
#endif
    
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    
    if (inet_aton((const char*)ip, &sa.sin_addr) != 1) {
        return -1;
    }
    
    return sendto(s, (const char*)data, len, flags, (struct sockaddr*)&sa, sizeof(sa));
}

// Send data to specific address (UDP) - IPv6
MOONBIT_FFI_EXPORT int moonbit_socket_sendto_ipv6(RAW_FD sockfd, moonbit_bytes_t data, int len, int moonbit_flags,
                                                   moonbit_bytes_t ip, uint16_t port) {
    int flags = map_flags(moonbit_flags);
#ifdef _WIN32
    SOCKET s = (SOCKET)sockfd;
#else
    int s = (int)sockfd;
#endif
    
    struct sockaddr_in6 sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons(port);
    
    if (inet_pton(AF_INET6, (const char*)ip, &sa.sin6_addr) != 1) {
        return -1;
    }
    
    return sendto(s, (const char*)data, len, flags, (struct sockaddr*)&sa, sizeof(sa));
}

// Receive data from any address (UDP)
MOONBIT_FFI_EXPORT int moonbit_socket_recvfrom(RAW_FD sockfd, moonbit_bytes_t buffer, int len, int moonbit_flags) {
    int flags = map_flags(moonbit_flags);
#ifdef _WIN32
    SOCKET s = (SOCKET)sockfd;
    return recvfrom(s, (char*)buffer, len, flags, NULL, NULL);
#else
    int s = (int)sockfd;
    return recvfrom(s, (char*)buffer, len, flags, NULL, NULL);
#endif
}

// Create a sender info structure, it not a nice design but it is simple
// and works for the purpose of getting sender info in UDP sockets.
MOONBIT_FFI_EXPORT moonbit_sender_info* moonbit_socket_create_sender_info(void) {
    moonbit_sender_info* info = (moonbit_sender_info*)malloc(sizeof(moonbit_sender_info));
    if (info) {
        info->addr_len = sizeof(info->addr);
    }
    return info;
}

// Free the sender info structure
MOONBIT_FFI_EXPORT void moonbit_socket_free_sender_info(moonbit_sender_info* info) {
    if (info) free(info);
}

// Receive data with sender info
MOONBIT_FFI_EXPORT int moonbit_socket_recvfrom_with_sender(
    RAW_FD sockfd, moonbit_bytes_t buffer, int len, int moonbit_flags, 
    moonbit_sender_info* info
) {
    if (!info) return -1;
    int flags = map_flags(moonbit_flags);
#ifdef _WIN32
    SOCKET s = (SOCKET)sockfd;
    return recvfrom(s, (char*)buffer, len, flags, 
                   (struct sockaddr*)&info->addr, &info->addr_len);
#else
    int s = (int)sockfd;
    return recvfrom(s, (char*)buffer, len, flags, 
                   (struct sockaddr*)&info->addr, &info->addr_len);
#endif
}

// Gets the sender IP address from the sender info structure
MOONBIT_FFI_EXPORT moonbit_bytes_t moonbit_socket_get_sender_ip(moonbit_sender_info* info) {
    if (!info) return NULL;
    
    char ip_str[INET6_ADDRSTRLEN];
    const struct sockaddr* sa = (const struct sockaddr*)&info->addr;
    
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *sa4 = (const struct sockaddr_in*)sa;
        inet_ntop(AF_INET, &sa4->sin_addr, ip_str, INET_ADDRSTRLEN);
    } else if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sa6 = (const struct sockaddr_in6*)sa;
        inet_ntop(AF_INET6, &sa6->sin6_addr, ip_str, INET6_ADDRSTRLEN);
    } else {
        return NULL;
    }
    
    int len_str = strlen(ip_str);
    moonbit_bytes_t result = moonbit_make_bytes(len_str, 0);
    if (result) memcpy(result, ip_str, len_str);
    return result;
}

// Gets the sender port from the sender info structure
MOONBIT_FFI_EXPORT uint16_t moonbit_socket_get_sender_port(moonbit_sender_info* info) {
    if (!info) return 0;
    
    const struct sockaddr* sa = (const struct sockaddr*)&info->addr;
    
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *sa4 = (const struct sockaddr_in*)sa;
        return ntohs(sa4->sin_port);
    } else if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sa6 = (const struct sockaddr_in6*)sa;
        return ntohs(sa6->sin6_port);
    }
    
    return 0;
}

// Set socket to non-blocking mode
MOONBIT_FFI_EXPORT int moonbit_socket_set_nonblocking(RAW_FD sockfd, int nonblocking) {
#ifdef _WIN32
    SOCKET s = (SOCKET)sockfd;
    u_long mode = nonblocking ? 1 : 0;
    return ioctlsocket(s, FIONBIO, &mode);
#else
    int s = (int)sockfd;
    int flags = fcntl(s, F_GETFL, 0);
    if (flags == -1) return -1;
    
    if (nonblocking) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }
    
    return fcntl(s, F_SETFL, flags);
#endif
}

// Set socket option (int value)
MOONBIT_FFI_EXPORT int moonbit_socket_setsockopt_int(RAW_FD sockfd, int level, int optname, int value) {
#ifdef _WIN32
    SOCKET s = (SOCKET)sockfd;
    return setsockopt(s, level, optname, (const char*)&value, sizeof(value));
#else
    int s = (int)sockfd;
    return setsockopt(s, level, optname, (const void*)&value, sizeof(value));
#endif
}

// Get socket option (int value)
MOONBIT_FFI_EXPORT int moonbit_socket_getsockopt_int(RAW_FD sockfd, int level, int optname) {
    int value = -1;
    socklen_t len = sizeof(value);
    
#ifdef _WIN32
    SOCKET s = (SOCKET)sockfd;
    if (getsockopt(s, level, optname, (char*)&value, &len) != 0) {
        return -1;
    }
#else
    int s = (int)sockfd;
    if (getsockopt(s, level, optname, &value, &len) != 0) {
        return -1;
    }
#endif
    
    return value;
}

// Get socket error
MOONBIT_FFI_EXPORT int moonbit_socket_get_error(void) {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

// Simple DNS resolution - returns first IPv4 address
MOONBIT_FFI_EXPORT moonbit_bytes_t moonbit_resolve_hostname_ipv4(moonbit_bytes_t hostname) {
    struct addrinfo hints, *result;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    int status = getaddrinfo((const char*)hostname, NULL, &hints, &result);
    if (status != 0) {
        return NULL;
    }
    
    moonbit_bytes_t ip_result = NULL;
    
    if (result && result->ai_family == AF_INET) {
        struct sockaddr_in *sa = (struct sockaddr_in*)result->ai_addr;
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sa->sin_addr, ip_str, INET_ADDRSTRLEN);
        
        int len = strlen(ip_str);
        ip_result = moonbit_make_bytes(len, 0);
        if (ip_result) memcpy(ip_result, ip_str, len);
    }
    
    freeaddrinfo(result);
    return ip_result;
}

// Simple DNS resolution - returns first IPv6 address
MOONBIT_FFI_EXPORT moonbit_bytes_t moonbit_resolve_hostname_ipv6(moonbit_bytes_t hostname) {
    struct addrinfo hints, *result;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    
    int status = getaddrinfo((const char*)hostname, NULL, &hints, &result);
    if (status != 0) {
        return NULL;
    }
    
    moonbit_bytes_t ip_result = NULL;
    
    if (result && result->ai_family == AF_INET6) {
        struct sockaddr_in6 *sa = (struct sockaddr_in6*)result->ai_addr;
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &sa->sin6_addr, ip_str, INET6_ADDRSTRLEN);
        
        int len = strlen(ip_str);
        ip_result = moonbit_make_bytes(len, 0);
        if (ip_result) memcpy(ip_result, ip_str, len);
    }
    
    freeaddrinfo(result);
    return ip_result;
}

// Constants for socket domains
MOONBIT_FFI_EXPORT int moonbit_AF_INET(void) { return AF_INET; }
MOONBIT_FFI_EXPORT int moonbit_AF_INET6(void) { return AF_INET6; }
MOONBIT_FFI_EXPORT int moonbit_AF_UNSPEC(void) { return AF_UNSPEC; }

// Constants for socket types
MOONBIT_FFI_EXPORT int moonbit_SOCK_STREAM(void) { return SOCK_STREAM; }
MOONBIT_FFI_EXPORT int moonbit_SOCK_DGRAM(void) { return SOCK_DGRAM; }
MOONBIT_FFI_EXPORT int moonbit_SOCK_RAW(void) { return SOCK_RAW; }

// Constants for socket protocols
MOONBIT_FFI_EXPORT int moonbit_IPPROTO_TCP(void) { return IPPROTO_TCP; }
MOONBIT_FFI_EXPORT int moonbit_IPPROTO_UDP(void) { return IPPROTO_UDP; }
MOONBIT_FFI_EXPORT int moonbit_IPPROTO_ICMP(void) { return IPPROTO_ICMP; }
MOONBIT_FFI_EXPORT int moonbit_IPPROTO_ICMPV6(void) { return IPPROTO_ICMPV6; }

// Constants for socket options
MOONBIT_FFI_EXPORT int moonbit_SOL_SOCKET(void) { return SOL_SOCKET; }
MOONBIT_FFI_EXPORT int moonbit_SO_REUSEADDR(void) { return SO_REUSEADDR; }
MOONBIT_FFI_EXPORT int moonbit_SO_KEEPALIVE(void) { return SO_KEEPALIVE; }
MOONBIT_FFI_EXPORT int moonbit_SO_RCVBUF(void) { return SO_RCVBUF; }
MOONBIT_FFI_EXPORT int moonbit_SO_SNDBUF(void) { return SO_SNDBUF; }

// Constants for socket shutdown modes
MOONBIT_FFI_EXPORT int moonbit_SHUT_RD(void) { return SHUT_RD; }
MOONBIT_FFI_EXPORT int moonbit_SHUT_WR(void) { return SHUT_WR; }
MOONBIT_FFI_EXPORT int moonbit_SHUT_RDWR(void) { return SHUT_RDWR; }

// Constants for send/recv flags
MOONBIT_FFI_EXPORT int moonbit_MSG_DONTWAIT(void) { 
#ifdef MSG_DONTWAIT
    return MSG_DONTWAIT; 
#else
    return 0;
#endif
}
MOONBIT_FFI_EXPORT int moonbit_MSG_PEEK(void) { return MSG_PEEK; }
