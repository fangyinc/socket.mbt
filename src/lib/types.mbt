///|
pub(all) suberror NetError String derive(Show)

///|
typealias Array as IOArray

///|
const AF_INET = 2 // IPv4

///|
const AF_INET6 = 10 // IPv6

///|
const AF_UNIX = 1 // Unix domain sockets

///|
pub(all) enum SocketAddr {
  V4(String, Int) // IPv4 address and port
  V6(String, Int) // IPv6 address and port
} derive(Show)

// pub(all) type Domain Int

///|
pub(all) enum Domain {
  IPv4
  IPv6
  Unix
} derive(Show)

///|
pub(all) enum Type {
  Stream // SOCK_STREAM
  Datagram // SOCK_DGRAM
  Raw // SOCK_RAW
} derive(Show)

///|
pub(all) enum Protocol {
  TCP // IPPROTO_TCP
  UDP // IPPROTO_UDP
  ICMPV4 // IPPROTO_ICMP
  ICMPV6 // IPPROTO_ICMPV6
} derive(Show)

///|
pub(all) enum Shutdown {
  Read // SHUT_RD
  Write // SHUT_WR
  Both // SHUT_RDWR
} derive(Show)

///|
pub fn Domain::inner(self : Domain) -> Int {
  match self {
    IPv4 => AF_INET
    IPv6 => AF_INET6
    Unix => AF_UNIX
  }
}

///|
pub fn Domain::from_address(addr : SocketAddr) -> Domain {
  match addr {
    V4(_, _) => IPv4
    V6(_, _) => IPv6
  }
}

///|
pub fn Type::inner(self : Type) -> Int {
  match self {
    Stream => 1 // SOCK_STREAM
    Datagram => 2 // SOCK_DGRAM
    Raw => 3 // SOCK_RAW
  }
}

///|
pub fn Protocol::inner(self : Protocol) -> Int {
  match self {
    TCP => 6 // IPPROTO_TCP
    UDP => 17 // IPPROTO_UDP
    ICMPV4 => 1 // IPPROTO_ICMP
    ICMPV6 => 58 // IPPROTO_ICMPV6
  }
}

///|
pub fn Shutdown::inner(self : Shutdown) -> Int {
  match self {
    Read => 0 // SHUT_RD
    Write => 1 // SHUT_WR
    Both => 2 // SHUT_RDWR
  }
}
