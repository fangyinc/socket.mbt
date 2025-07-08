///|
fn main {
  (try? run_tcp_server())
  .map_err(fn(err) { println("Error starting TCP server: " + err.to_string()) })
  .unwrap()
}

///|
fn run_tcp_server() -> Unit raise @socket.NetError {
  let socket = @socket.new(@socket.Domain::IPv4, @socket.Type::Stream)
  let addr = @socket.SocketAddr::V4("127.0.0.1", 8180)
  socket..bind(addr)..listen()
  while true {
    let client = match (try? socket.accept()) {
      Ok(l) => l
      Err(err) => {
        println("Failed to accept connection: " + err.to_string())
        continue
      }
    }
    // Handle client connection in a separate function or thread
    handle_client(client)
    client.close()
  }
}

///|
fn handle_client(client : @socket.Socket) -> Unit {
  // Here you can read from and write to the client socket
  // For example, you can read data from the client and echo it back
  while true {
    let buf = FixedArray::make(1024, Byte::default())
    let bytes_read = match (try? client.recv(buf)) {
      Ok(n) => n
      Err(err) => {
        println("Failed to read from client: " + err.to_string())
        return
      }
    }
    if bytes_read == 0 {
      println("Client disconnected")
      return
    }
    guard (try? @socket.utf8_bytes_to_mbt_string(@bytes.from_fixedarray(buf)))
      is Ok(str_req) else {
      println("Failed to decode UTF-8 string from client data")
      return
    }
    println("Received from client: " + str_req)
    let reply_str =
      $|Reply from TCP Server, your req: \{str_req}
    let reply_bytes = @socket.mbt_string_to_utf8_bytes(reply_str, false)
    let reply = FixedArray::from_iter(reply_bytes.iter())
    // Echo back the received data
    match (try? client.send(reply, reply.length())) {
      Ok(_) => println("Echoed back " + bytes_read.to_string() + " bytes")
      Err(err) => {
        println("Failed to write to client: " + err.to_string())
        return
      }
    }
  }
}
