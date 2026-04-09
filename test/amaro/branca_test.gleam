import amaro/branca
import gleam/bit_array
import gleam/time/duration
import gleam/time/timestamp

fn test_key() -> branca.Key {
  let assert Ok(key) =
    bit_array.base16_decode(
      "73757065727365637265746B6579796F7573686F756C646E6F74636F6D6D6974",
    )
  let assert Ok(key) = branca.key_from_bytes(bytes: key)
  key
}

fn test_nonce() -> BitArray {
  let assert Ok(nonce) =
    bit_array.base16_decode("BEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEF")
  nonce
}

pub fn encrypt_hello_zero_timestamp_test() {
  let key = test_key()
  let nonce = test_nonce()
  let now = timestamp.from_unix_seconds(0)
  let assert Ok(token) =
    branca.encrypt_with(key, plaintext: <<"Hello world!":utf8>>, now:, nonce:)

  assert token
    == "870S4BYxgHw0KnP3W9fgVUHEhT5g86vJ17etaC5Kh5uIraWHCI1psNQGv298ZmjPwoYbjDQ9chy2z"
}

pub fn encrypt_hello_max_timestamp_test() {
  let key = test_key()
  let nonce = test_nonce()
  let now = timestamp.from_unix_seconds(4_294_967_295)
  let assert Ok(token) =
    branca.encrypt_with(key, plaintext: <<"Hello world!":utf8>>, now:, nonce:)

  assert token
    == "89i7YCwu5tWAJNHUDdmIqhzOi5hVHOd4afjZcGMcVmM4enl4yeLiDyYv41eMkNmTX6IwYEFErCSqr"
}

pub fn encrypt_hello_nov27_timestamp_test() {
  let key = test_key()
  let nonce = test_nonce()
  let now = timestamp.from_unix_seconds(123_206_400)
  let assert Ok(token) =
    branca.encrypt_with(key, plaintext: <<"Hello world!":utf8>>, now:, nonce:)

  assert token
    == "875GH23U0Dr6nHFA63DhOyd9LkYudBkX8RsCTOMz5xoYAMw9sMd5QwcEqLDRnTDHPenOX7nP2trlT"
}

pub fn encrypt_null_bytes_test() {
  let key = test_key()
  let nonce = test_nonce()
  let now = timestamp.from_unix_seconds(0)
  let assert Ok(msg) = bit_array.base16_decode("0000000000000000")
  let assert Ok(token) = branca.encrypt_with(key, plaintext: msg, now:, nonce:)

  assert token
    == "1jIBheHbDdkCDFQmtgw4RUZeQoOJgGwTFJSpwOAk3XYpJJr52DEpILLmmwYl4tjdSbbNqcF1"
}

pub fn encrypt_empty_payload_test() {
  let key = test_key()
  let nonce = test_nonce()
  let now = timestamp.from_unix_seconds(0)
  let assert Ok(token) = branca.encrypt_with(key, plaintext: <<>>, now:, nonce:)

  assert token
    == "4sfD0vPFhIif8cy4nB3BQkHeJqkOkDvinI4zIhMjYX4YXZU5WIq9ycCVjGzB5"
}

pub fn decrypt_hello_zero_timestamp_test() {
  let key = test_key()
  let assert Ok(plaintext) =
    branca.decrypt(
      key,
      token: "870S4BYxgHw0KnP3W9fgVUHEhT5g86vJ17etaC5Kh5uIraWHCI1psNQGv298ZmjPwoYbjDQ9chy2z",
    )

  assert plaintext == <<"Hello world!":utf8>>
}

pub fn decrypt_hello_max_timestamp_test() {
  let key = test_key()
  let assert Ok(plaintext) =
    branca.decrypt(
      key,
      token: "89i7YCwu5tWAJNHUDdmIqhzOi5hVHOd4afjZcGMcVmM4enl4yeLiDyYv41eMkNmTX6IwYEFErCSqr",
    )

  assert plaintext == <<"Hello world!":utf8>>
}

pub fn decrypt_empty_payload_test() {
  let key = test_key()
  let assert Ok(plaintext) =
    branca.decrypt(
      key,
      token: "4sfD0vPFhIif8cy4nB3BQkHeJqkOkDvinI4zIhMjYX4YXZU5WIq9ycCVjGzB5",
    )

  assert plaintext == <<>>
}

pub fn roundtrip_test() {
  let key = branca.generate_key()
  let message = <<"round trip message":utf8>>
  let token = branca.encrypt(key, plaintext: message)
  let assert Ok(plaintext) = branca.decrypt(key, token:)

  assert plaintext == message
}

pub fn roundtrip_empty_message_test() {
  let key = branca.generate_key()
  let token = branca.encrypt(key, plaintext: <<>>)
  let assert Ok(plaintext) = branca.decrypt(key, token:)

  assert plaintext == <<>>
}

pub fn key_roundtrip_test() {
  let key = branca.generate_key()
  let bytes = branca.key_to_bytes(key)
  let assert Ok(decoded) = branca.key_from_bytes(bytes:)

  assert branca.key_to_bytes(decoded) == bytes
}

pub fn invalid_key_too_short_test() {
  let result = branca.key_from_bytes(bytes: <<1, 2, 3>>)

  assert result == Error(branca.InvalidKey)
}

pub fn invalid_token_garbage_test() {
  let key = branca.generate_key()
  let result = branca.decrypt(key, token: "not-a-valid-token!!!")

  assert result == Error(branca.InvalidToken)
}

pub fn invalid_token_too_short_test() {
  let key = branca.generate_key()
  let result = branca.decrypt(key, token: "abc")

  assert result == Error(branca.InvalidToken)
}

pub fn invalid_version_test() {
  let key = test_key()
  let result =
    branca.decrypt(
      key,
      token: "89mvl3RkwXjpEj5WMxK7GUDEHEeeeZtwjMIOogTthvr44qBfYtQSIZH5MHOTC0GzoutDIeoPVZk3w",
    )

  assert result == Error(branca.InvalidVersion)
}

pub fn wrong_key_test() {
  let assert Ok(wrong_key) =
    bit_array.base16_decode(
      "77726F6E677365637265746B6579796F7573686F756C646E6F74636F6D6D6974",
    )
  let assert Ok(wrong_key) = branca.key_from_bytes(bytes: wrong_key)
  let result =
    branca.decrypt(
      wrong_key,
      token: "870S4BYxgHw0KnP3W9fgVUHEhT5g86vJ17etaC5Kh5uIraWHCI1psNQGv298ZmjPwoYbjDQ9chy2z",
    )

  assert result == Error(branca.DecryptionFailed)
}

pub fn tampered_ciphertext_test() {
  let key = test_key()
  let result =
    branca.decrypt(
      key,
      token: "875GH23U0Dr6nHFA63DhOyd9LkYudBkX8RsCTOMz5xoYAMw9sMd5Qw6Jpo96myliI3hHD7VbKZBYh",
    )

  assert result == Error(branca.DecryptionFailed)
}

pub fn tampered_tag_test() {
  let key = test_key()
  let result =
    branca.decrypt(
      key,
      token: "875GH23U0Dr6nHFA63DhOyd9LkYudBkX8RsCTOMz5xoYAMw9sMd5QwcEqLDRnTDHPenOX7nP2trk0",
    )

  assert result == Error(branca.DecryptionFailed)
}

pub fn modified_nonce_test() {
  let key = test_key()
  let result =
    branca.decrypt(
      key,
      token: "875GH233SUysT7fQ711EWd9BXpwOjB72ng3ZLnjWFrmOqVy49Bv93b78JU5331LbcY0EEzhLfpmSx",
    )

  assert result == Error(branca.DecryptionFailed)
}

pub fn modified_timestamp_test() {
  let key = test_key()
  let result =
    branca.decrypt(
      key,
      token: "870g1RCk4lW1YInhaU3TP8u2hGtfol16ettLcTOSoA0JIpjCaQRW7tQeP6dQmTvFIB2s6wL5deMXr",
    )

  assert result == Error(branca.DecryptionFailed)
}

pub fn decrypt_with_ttl_valid_test() {
  let key = branca.generate_key()
  let token = branca.encrypt(key, plaintext: <<"fresh":utf8>>)
  let assert Ok(plaintext) =
    branca.decrypt_with_ttl(key, token:, ttl: duration.seconds(60))

  assert plaintext == <<"fresh":utf8>>
}

pub fn decrypt_with_ttl_expired_test() {
  let key = branca.generate_key()
  let nonce = test_nonce()
  let old_time = timestamp.from_unix_seconds(1_000_000)
  let assert Ok(token) =
    branca.encrypt_with(key, plaintext: <<"old":utf8>>, now: old_time, nonce:)
  let result = branca.decrypt_with_ttl(key, token:, ttl: duration.seconds(60))

  assert result == Error(branca.TokenExpired)
}
