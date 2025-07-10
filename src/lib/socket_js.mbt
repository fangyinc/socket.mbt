///|
typealias Int64 as RawFd

///|
pub(all) struct Socket {
  inner : RawFd
} derive(Show)

///|
fn socket_create_internal(
  domain : Int,
  t : Int,
  protocol : Int,
) -> RawFd raise NetError {
  ...
}

///|
fn socket_close_internal(sockfd : RawFd) -> Unit raise NetError {
  ...
}

///| Shutdown a socket.
/// Returns 0 on success, -1 on error.
fn socket_shutdown_internal(
  sockfd : RawFd,
  how : Shutdown,
) -> Unit raise NetError {
  ...
}

///| Set socket options.
/// Returns 0 on success, -1 on error.
fn socket_setsockopt_internal(
  sockfd : RawFd,
  level : Int,
  optname : Int,
  optval : Int,
) -> Unit raise NetError {
  ...
}

///|
fn socket_bind_internal(
  sockfd : RawFd,
  addr : SocketAddr,
) -> Unit raise NetError {
  ...
}

///|
fn socket_listen_internal(sockfd : RawFd, backlog : Int) -> Unit raise NetError {
  ...
}

///|
fn socket_accept_internal(sockfd : RawFd) -> RawFd raise NetError {
  ...
}

///|
fn socket_connect_internal(
  sockfd : RawFd,
  addr : SocketAddr,
) -> Unit raise NetError {
  ...
}

///|
fn socket_send_internal(
  sockfd : RawFd,
  data : FixedArray[Byte],
  len : Int,
  flags : Int,
) -> Int raise NetError {
  ...
}

///|
fn socket_recv_internal(
  sockfd : RawFd,
  buf : FixedArray[Byte],
  len : Int,
  flags : Int,
) -> Int raise NetError {
  ...
}

///|
fn get_net_error_message() -> String {
  ...
}
