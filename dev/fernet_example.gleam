import amaro/fernet
import gleam/bit_array
import gleam/io
import gleam/time/duration

pub fn main() {
  let key = fernet.generate_key()

  let token = fernet.encrypt(key, plaintext: <<"hello, fernet!":utf8>>)
  io.println("Token: " <> token)

  let assert Ok(plaintext) = fernet.decrypt(key, token:)
  let assert Ok(message) = bit_array.to_string(plaintext)
  io.println("Decrypted: " <> message)

  let encoded = fernet.key_to_string(key)
  io.println("Key: " <> encoded)

  let assert Ok(restored_key) = fernet.key_from_string(encoded:)
  let assert Ok(plaintext) = fernet.decrypt(restored_key, token:)
  let assert Ok(message) = bit_array.to_string(plaintext)
  io.println("Decrypted with restored key: " <> message)

  let assert Ok(plaintext) =
    fernet.decrypt_with_ttl(key, token:, ttl: duration.seconds(60))
  let assert Ok(message) = bit_array.to_string(plaintext)
  io.println("Decrypted with 60s TTL: " <> message)
}
