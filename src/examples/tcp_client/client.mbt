///|
fn main {
  (try? run_tcp_client())
  .map_err(fn(err) { println("Error starting TCP client: " + err.to_string()) })
  .unwrap()
}

///|
fn run_tcp_client() -> Unit raise @socket.NetError {
  let socket = @socket.new(@socket.Domain::IPv4, @socket.Type::Stream)
  let addr = @socket.SocketAddr::V4("127.0.0.1", 8180)
  socket.connect(addr)
  let bytes : FixedArray[Byte] = FixedArray::from_iter(b"你好呀\n".iter())
  
  let _ = socket.send(bytes, bytes.length())

  let buf: FixedArray[Byte] = FixedArray::make(1024, 0)

  let bytes_read = match (try? socket.recv(buf)) {
    Ok(n) => n
    Err(err) => {
      println("Failed to read from server: " + err.to_string())
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
  
  println("Received from server: " + str_req)
  socket.close()
}