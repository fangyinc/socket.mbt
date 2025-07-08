
// typealias Int as RawFd

///|
typealias Int64 as RawFd

///|
pub(all) struct Socket {
  inner : RawFd
} derive(Show)

///|
extern "C" fn socket_init_ffi() -> Int = "moonbit_socket_init"

///|
extern "C" fn socket_create_ffi(domain : Int, t : Int, protocol : Int) -> RawFd = "moonbit_socket_create"

///|
extern "C" fn socket_close_ffi(sockfd : RawFd) -> Int = "moonbit_socket_close"

///| Shutdown a socket.
/// Returns 0 on success, -1 on error.
extern "C" fn socket_shutdown_ffi(sockfd : RawFd, how : Int) -> Int = "moonbit_socket_shutdown"

///| 
extern "C" fn socket_setsockopt(
  sockfd : RawFd,
  level : Int,
  optname : Int,
  optval : Int
) -> Int = "moonbit_socket_setsockopt_int"

///| Bind a socket to an address.
/// Success return a non-negative integer, -1 on error.
extern "C" fn socket_bind_ipv4_ffi(
  sockfd : RawFd,
  host : Bytes,
  port : Int
) -> Int = "moonbit_socket_bind_ipv4"

///| Bind a socket to an IPv6 address.
/// Success return a non-negative integer, -1 on error.
extern "C" fn socket_bind_ipv6_ffi(
  sockfd : RawFd,
  host : Bytes,
  port : Int
) -> Int = "moonbit_socket_bind_ipv6"

///| Listen for incoming connections on a socket.
/// Returns 0 on success, -1 on error.
/// The `sockfd` parameter is the file descriptor of the socket to listen on.
/// The `backlog` parameter specifies the maximum length of the queue of pending connections.
extern "C" fn socket_listen_ffi(sockfd : RawFd, backlog : Int) -> Int = "moonbit_socket_listen"

///|
extern "C" fn socket_accept_ffi(sockfd : RawFd) -> RawFd = "moonbit_socket_accept"

///|
extern "C" fn socket_connect_ipv4_ffi(
  sockfd : RawFd,
  host : Bytes,
  port : Int
) -> Int = "moonbit_socket_connect_ipv4"

///|
extern "C" fn socket_connect_ipv6_ffi(
  sockfd : RawFd,
  host : Bytes,
  port : Int
) -> Int = "moonbit_socket_connect_ipv6"

///| Send data to a socket.
/// Returns the number of bytes sent, or -1 on error, or 0 if the remote side has closed the connection.
extern "C" fn socket_send_ffi(
  sockfd : RawFd,
  data : FixedArray[Byte],
  len : Int,
  flags : Int
) -> Int = "moonbit_socket_send"

///| Receive data from a socket.
/// Returns the number of bytes received, or -1 on error.
/// The `buf` parameter is a mutable byte array where the received data will be stored.
/// The `len` parameter specifies the maximum number of bytes to read.
/// The `flags` parameter can be used to specify additional options for the receive operation.
extern "C" fn socket_recv_ffi(
  sockfd : RawFd,
  buf : FixedArray[Byte],
  len : Int,
  flags : Int
) -> Int = "moonbit_socket_recv"

///|
extern "C" fn get_net_error_message_ffi() -> Bytes = "moonbit_get_error_message"

///|
fn socket_create_internal(
  domain : Int,
  t : Int,
  protocol : Int
) -> RawFd raise NetError {
  guard socket_init_ffi() == 0 else { raise NetError(get_net_error_message()) }
  let sockfd = socket_create_ffi(domain, t, protocol)
  guard sockfd >= 0 else { raise NetError(get_net_error_message()) }
  return sockfd
}

///|
fn socket_close_internal(sockfd : RawFd) -> Unit raise NetError {
  guard socket_close_ffi(sockfd) == 0 else {
    raise NetError(get_net_error_message())
  }
}

///| Shutdown a socket.
/// Returns 0 on success, -1 on error.
fn socket_shutdown_internal(sockfd : RawFd, how : Shutdown) -> Unit raise NetError {
  guard socket_shutdown_ffi(sockfd, how.inner()) == 0 else {
    raise NetError(get_net_error_message())
  }
}

///| Set socket options.
/// Returns 0 on success, -1 on error.
fn socket_setsockopt_internal(
  sockfd : RawFd,
  level : Int,
  optname : Int,
  optval : Int
) -> Unit raise NetError {
  guard socket_setsockopt(sockfd, level, optname, optval) >= 0 else {
    raise NetError(get_net_error_message())
  }
}


///|
fn socket_bind_internal(
  sockfd : RawFd,
  addr : SocketAddr
) -> Unit raise NetError {
  let res = match addr {
    V4(host, port) =>
      socket_bind_ipv4_ffi(
        sockfd,
        mbt_string_to_utf8_bytes(host, true),
        port,
      )
    V6(host, port) =>
      socket_bind_ipv6_ffi(
        sockfd,
        mbt_string_to_utf8_bytes(host, true),
        port,
      )
  }
  guard res >= 0 else { raise NetError(get_net_error_message()) }
}

///|
fn socket_listen_internal(sockfd : RawFd, backlog : Int) -> Unit raise NetError {
  guard socket_listen_ffi(sockfd, backlog) >= 0 else {
    raise NetError(get_net_error_message())
  }
}

///|
fn socket_accept_internal(sockfd : RawFd) -> RawFd raise NetError {
  let clientfd = socket_accept_ffi(sockfd)
  guard clientfd >= 0 else { raise NetError(get_net_error_message()) }
  return clientfd
}

///|
fn socket_connect_internal(
  sockfd : RawFd,
  addr : SocketAddr
) -> Unit raise NetError {
  let res = match addr {
    V4(host, port) =>
      socket_connect_ipv4_ffi(
        sockfd,
        mbt_string_to_utf8_bytes(host, true),
        port,
      )
    V6(host, port) =>
      socket_connect_ipv6_ffi(
        sockfd,
        mbt_string_to_utf8_bytes(host, true),
        port,
      )
  }
  guard res >= 0 else { raise NetError(get_net_error_message()) }
}

///|
fn socket_send_internal(
  sockfd : RawFd,
  data : FixedArray[Byte],
  len : Int,
  flags : Int
) -> Int raise NetError {
  let bytes_sent = socket_send_ffi(sockfd, data, len, flags)
  guard bytes_sent >= 0 else { raise NetError(get_net_error_message()) }
  return bytes_sent
}

///|
fn socket_recv_internal(
  sockfd : RawFd,
  buf : FixedArray[Byte],
  len : Int,
  flags : Int
) -> Int raise NetError {
  let bytes_received = socket_recv_ffi(sockfd, buf, len, flags)
  guard bytes_received >= 0 else { raise NetError(get_net_error_message()) }
  return bytes_received
}

///|
fn get_net_error_message() -> String {
  let res = try?(utf8_bytes_to_mbt_string(get_net_error_message_ffi()))
  match res {
    Ok(msg) => msg
    Err(_) => "Unknown error".to_string()
  }
}
