///|
pub fn mbt_string_to_utf8_bytes(str : String, is_filename : Bool) -> Bytes {
  let buf = @buffer.new()
  @encoding.encode_to(str, buf, encoding=UTF8)
  if is_filename {
    buf.write_byte((0).to_byte())
  }
  buf.to_bytes()
}

///|
pub fn utf8_bytes_to_mbt_string(bytes : Bytes) -> String raise {
  let decoder = @encoding.decoder(UTF8)
  decoder.consume(bytes)
}
