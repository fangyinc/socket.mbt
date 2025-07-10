///|
pub fn new(
  domain : Domain,
  ty : Type,
  protocol~ : Protocol? = None,
) -> Socket raise NetError {
  let domain : Int = domain.inner()
  let ty : Int = ty.inner()
  let protocol : Int = protocol.map_or(0, fn(p) { p.inner() })
  let sockfd = socket_create_internal(domain, ty, protocol)
  guard sockfd >= 0 else { raise NetError("Failed to create socket") }
  Socket::{ inner: sockfd }
}

///|
pub fn Socket::bind(self : Socket, addr : SocketAddr) -> Unit raise NetError {
  socket_bind_internal(self.inner, addr)
}

///|
pub fn Socket::listen(self : Socket, backlog~ : Int = 5) -> Unit raise NetError {
  socket_listen_internal(self.inner, backlog)
}

///|
pub fn Socket::accept(self : Socket) -> Socket raise NetError {
  let clientfd = socket_accept_internal(self.inner)
  guard clientfd >= 0 else { raise NetError("Failed to accept connection") }
  Socket::{ inner: clientfd }
}

///|
pub fn Socket::connect(self : Socket, addr : SocketAddr) -> Unit raise NetError {
  socket_connect_internal(self.inner, addr)
}

///|
pub fn Socket::send(
  self : Socket,
  data : FixedArray[Byte],
  len : Int,
  flags~ : Int = 0,
) -> Int raise NetError {
  socket_send_internal(self.inner, data, len, flags)
}

///|
pub fn Socket::recv(
  self : Socket,
  buffer : FixedArray[Byte],
  flags~ : Int = 0,
) -> Int raise NetError {
  socket_recv_internal(self.inner, buffer, buffer.length(), flags)
}

///|
pub fn Socket::close(self : Socket) -> Unit raise NetError {
  socket_close_internal(self.inner)
}

///|
pub fn Socket::shutdown(self : Socket, how : Shutdown) -> Unit raise NetError {
  socket_shutdown_internal(self.inner, how)
}

///|
pub fn Socket::set_broadcast(
  self : Socket,
  enable : Bool,
) -> Unit raise NetError {
  let level = 1 // SOL_SOCKET
  let optname = 6 // SO_BROADCAST
  let optval = if enable { 1 } else { 0 }
  socket_setsockopt_internal(self.inner, level, optname, optval)
}

///|
pub fn Socket::set_keepalive(
  self : Socket,
  enable : Bool,
) -> Unit raise NetError {
  let level = 1 // SOL_SOCKET
  let optname = 9 // SO_KEEPALIVE
  let optval = if enable { 1 } else { 0 }
  socket_setsockopt_internal(self.inner, level, optname, optval)
}

///|
pub fn Socket::set_recv_buffer_size(
  self : Socket,
  size : Int,
) -> Unit raise NetError {
  let level = 1 // SOL_SOCKET
  let optname = 8 // SO_RCVBUF
  socket_setsockopt_internal(self.inner, level, optname, size)
}

///|
pub fn Socket::set_send_buffer_size(
  self : Socket,
  size : Int,
) -> Unit raise NetError {
  let level = 1 // SOL_SOCKET
  let optname = 7 // SO_SNDBUF
  socket_setsockopt_internal(self.inner, level, optname, size)
}

///|
pub fn Socket::setsockopt(
  self : Socket,
  level : Int,
  optname : Int,
  optval : Int,
) -> Unit raise NetError {
  socket_setsockopt_internal(self.inner, level, optname, optval)
}
