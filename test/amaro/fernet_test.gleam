import amaro/fernet
import gleam/bit_array
import gleam/time/duration
import gleam/time/timestamp

fn test_key() -> fernet.Key {
  let assert Ok(key) =
    fernet.key_from_string(
      encoded: "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
    )
  key
}

fn test_iv() -> BitArray {
  <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>
}

pub fn encrypt_known_vector_test() {
  let key = test_key()
  let iv = test_iv()
  let now = timestamp.from_unix_seconds(499_162_800)
  let assert Ok(token) =
    fernet.encrypt_with(key, plaintext: <<"hello":utf8>>, now:, iv:)

  assert token
    == "gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA=="
}

pub fn decrypt_known_vector_test() {
  let key = test_key()
  let token =
    "gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA=="
  let assert Ok(plaintext) = fernet.decrypt(key, token:)

  assert plaintext == <<"hello":utf8>>
}

pub fn roundtrip_test() {
  let key = fernet.generate_key()
  let message = <<"round trip message":utf8>>
  let token = fernet.encrypt(key, plaintext: message)
  let assert Ok(plaintext) = fernet.decrypt(key, token:)

  assert plaintext == message
}

pub fn roundtrip_empty_message_test() {
  let key = fernet.generate_key()
  let message = <<>>
  let token = fernet.encrypt(key, plaintext: message)
  let assert Ok(plaintext) = fernet.decrypt(key, token:)

  assert plaintext == message
}

pub fn key_roundtrip_test() {
  let key = fernet.generate_key()
  let encoded = fernet.key_to_string(key)
  let assert Ok(decoded) = fernet.key_from_string(encoded:)

  assert fernet.key_to_string(decoded) == encoded
}

pub fn invalid_key_too_short_test() {
  let result =
    fernet.key_from_string(encoded: bit_array.base64_url_encode(
      <<1, 2, 3>>,
      True,
    ))

  assert result == Error(fernet.InvalidKey)
}

pub fn invalid_key_bad_base64_test() {
  let result = fernet.key_from_string(encoded: "not valid base64!!!")

  assert result == Error(fernet.InvalidKey)
}

pub fn invalid_token_garbage_test() {
  let key = fernet.generate_key()
  let result = fernet.decrypt(key, token: "not-a-valid-token!!!")

  assert result == Error(fernet.InvalidToken)
}

pub fn invalid_token_too_short_test() {
  let key = fernet.generate_key()
  let short = bit_array.base64_url_encode(<<0x80, 1, 2, 3>>, True)
  let result = fernet.decrypt(key, token: short)

  assert result == Error(fernet.InvalidToken)
}

pub fn invalid_version_test() {
  let key = fernet.generate_key()
  let token = fernet.encrypt(key, plaintext: <<"hello":utf8>>)
  let assert Ok(data) = bit_array.base64_url_decode(token)
  let assert <<_version:8, rest:bits>> = data
  let tampered = bit_array.base64_url_encode(<<0x00, rest:bits>>, True)
  let result = fernet.decrypt(key, token: tampered)

  assert result == Error(fernet.InvalidVersion)
}

pub fn invalid_signature_test() {
  let key = fernet.generate_key()
  let token = fernet.encrypt(key, plaintext: <<"hello":utf8>>)
  let assert Ok(data) = bit_array.base64_url_decode(token)
  let size = bit_array.byte_size(data)
  let assert Ok(payload) = bit_array.slice(data, 0, size - 32)
  let tampered =
    bit_array.base64_url_encode(<<payload:bits, 0:size(256)>>, True)
  let result = fernet.decrypt(key, token: tampered)

  assert result == Error(fernet.InvalidSignature)
}

pub fn wrong_key_test() {
  let key1 = fernet.generate_key()
  let key2 = fernet.generate_key()
  let token = fernet.encrypt(key1, plaintext: <<"secret":utf8>>)
  let result = fernet.decrypt(key2, token:)

  assert result == Error(fernet.InvalidSignature)
}

pub fn decrypt_with_ttl_valid_test() {
  let key = fernet.generate_key()
  let token = fernet.encrypt(key, plaintext: <<"fresh":utf8>>)
  let assert Ok(plaintext) =
    fernet.decrypt_with_ttl(key, token:, ttl: duration.seconds(60))

  assert plaintext == <<"fresh":utf8>>
}

pub fn decrypt_with_ttl_expired_test() {
  let key = fernet.generate_key()
  let old_time = timestamp.from_unix_seconds(1_000_000)
  let iv = test_iv()
  let assert Ok(token) =
    fernet.encrypt_with(key, plaintext: <<"old":utf8>>, now: old_time, iv:)
  let result = fernet.decrypt_with_ttl(key, token:, ttl: duration.seconds(60))

  assert result == Error(fernet.TokenExpired)
}
