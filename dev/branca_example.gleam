import amaro/branca
import gleam/bit_array
import gleam/io
import gleam/time/duration

pub fn main() {
  let key = branca.generate_key()

  let token = branca.encrypt(key, plaintext: <<"hello, branca!":utf8>>)
  io.println("Token: " <> token)

  let assert Ok(plaintext) = branca.decrypt(key, token:)
  let assert Ok(message) = bit_array.to_string(plaintext)
  io.println("Decrypted: " <> message)

  let bytes = branca.key_to_bytes(key)
  let assert Ok(restored_key) = branca.key_from_bytes(bytes:)
  let assert Ok(plaintext) = branca.decrypt(restored_key, token:)
  let assert Ok(message) = bit_array.to_string(plaintext)
  io.println("Decrypted with restored key: " <> message)

  let assert Ok(plaintext) =
    branca.decrypt_with_ttl(key, token:, ttl: duration.seconds(60))
  let assert Ok(message) = bit_array.to_string(plaintext)
  io.println("Decrypted with 60s TTL: " <> message)
}
