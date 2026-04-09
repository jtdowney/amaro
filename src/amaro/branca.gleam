//// Encrypt and decrypt [Branca](https://github.com/tuupola/branca-spec) tokens.
////
//// Branca tokens use XChaCha20-Poly1305 authenticated encryption. Tokens are
//// base62-encoded and URL-safe.
////
//// ## Example
////
//// ```gleam
//// let key = branca.generate_key()
//// let token = branca.encrypt(key, plaintext: <<"hello":utf8>>)
//// let assert Ok(plaintext) = branca.decrypt(key, token:)
//// ```

import gleam/bit_array
import gleam/bool
import gleam/option.{type Option}
import gleam/order
import gleam/result
import gleam/time/duration.{type Duration}
import gleam/time/timestamp.{type Timestamp}
import kryptos/aead
import kryptos/crypto
import sixtytwo

const version = 0xBA

const key_size = 32

const nonce_size = 24

const header_size = 29

const tag_size = 16

/// A 256-bit key for XChaCha20-Poly1305 authenticated encryption.
/// Generate one with `generate_key` or wrap existing bytes with
/// `key_from_bytes`.
pub opaque type Key {
  Key(data: BitArray)
}

/// Errors that can occur during key parsing or token operations.
pub type Error {
  /// Key is not exactly 32 bytes.
  InvalidKey
  /// Token is not valid base62 or is too short to contain all fields.
  InvalidToken
  /// Token version byte is not 0xBA.
  InvalidVersion
  /// Token age exceeds the TTL passed to `decrypt_with_ttl`.
  TokenExpired
  /// AEAD decryption failed. The token was tampered with or the wrong
  /// key was used.
  DecryptionFailed
}

/// Generate a random Branca key using a cryptographically secure RNG.
pub fn generate_key() -> Key {
  Key(crypto.random_bytes(key_size))
}

/// Wrap raw bytes as a Branca key. The input must be exactly 32 bytes.
pub fn key_from_bytes(bytes bytes: BitArray) -> Result(Key, Error) {
  case bit_array.byte_size(bytes) == key_size {
    True -> Ok(Key(bytes))
    False -> Error(InvalidKey)
  }
}

/// Return the raw 32 bytes of the key.
pub fn key_to_bytes(key: Key) -> BitArray {
  key.data
}

/// Encrypt plaintext into a Branca token string. The current system time is
/// recorded in the token and a random nonce is generated for each call.
pub fn encrypt(key: Key, plaintext plaintext: BitArray) -> String {
  let now = timestamp.system_time()
  let nonce = crypto.random_bytes(nonce_size)
  let assert Ok(token) = encrypt_with(key, plaintext:, now:, nonce:)
  token
}

@internal
pub fn encrypt_with(
  key: Key,
  plaintext plaintext: BitArray,
  now now: Timestamp,
  nonce nonce: BitArray,
) -> Result(String, Error) {
  let #(seconds, _nanoseconds) = timestamp.to_unix_seconds_and_nanoseconds(now)
  let header = <<version, seconds:big-size(32), nonce:bits>>

  use ctx <- result.try(
    aead.xchacha20_poly1305(key.data)
    |> result.replace_error(InvalidKey),
  )
  use #(ciphertext, tag) <- result.map(
    aead.seal_with_aad(ctx, nonce:, plaintext:, additional_data: header)
    |> result.replace_error(DecryptionFailed),
  )

  sixtytwo.encode(<<header:bits, ciphertext:bits, tag:bits>>)
}

/// Decrypt a Branca token and return the original plaintext. No expiry check
/// is performed.
pub fn decrypt(key: Key, token token: String) -> Result(BitArray, Error) {
  do_decrypt(key, token, option.None)
}

/// Decrypt a Branca token, rejecting it if its age exceeds `ttl`. Age is
/// measured as the difference between the current system time and the
/// timestamp embedded in the token.
pub fn decrypt_with_ttl(
  key: Key,
  token token: String,
  ttl ttl: Duration,
) -> Result(BitArray, Error) {
  do_decrypt(key, token, option.Some(ttl))
}

fn do_decrypt(
  key: Key,
  token: String,
  ttl: Option(Duration),
) -> Result(BitArray, Error) {
  use data <- result.try(
    sixtytwo.decode(token)
    |> result.replace_error(InvalidToken),
  )

  let min_size = header_size + tag_size
  use <- bool.guard(
    when: bit_array.byte_size(data) < min_size,
    return: Error(InvalidToken),
  )

  use #(token_version, token_timestamp, nonce, ciphertext, tag) <- result.try(
    parse_token(data),
  )

  use <- guard_version(token_version)
  use <- guard_ttl(token_timestamp, ttl)

  let assert Ok(header) = bit_array.slice(data, 0, header_size)

  use ctx <- result.try(
    aead.xchacha20_poly1305(key.data)
    |> result.replace_error(InvalidKey),
  )

  aead.open_with_aad(ctx, nonce:, tag:, ciphertext:, additional_data: header)
  |> result.replace_error(DecryptionFailed)
}

fn parse_token(
  data: BitArray,
) -> Result(#(Int, Int, BitArray, BitArray, BitArray), Error) {
  let ct_size = bit_array.byte_size(data) - header_size - tag_size
  case data {
    <<
      version:int,
      timestamp:big-unsigned-size(32),
      nonce:bytes-size(nonce_size),
      ciphertext:bytes-size(ct_size),
      tag:bytes-size(tag_size),
    >> -> Ok(#(version, timestamp, nonce, ciphertext, tag))
    _ -> Error(InvalidToken)
  }
}

fn guard_version(
  token_version: Int,
  next: fn() -> Result(BitArray, Error),
) -> Result(BitArray, Error) {
  case token_version == version {
    True -> next()
    False -> Error(InvalidVersion)
  }
}

fn guard_ttl(
  token_timestamp: Int,
  ttl: Option(Duration),
  next: fn() -> Result(BitArray, Error),
) -> Result(BitArray, Error) {
  case ttl {
    option.None -> next()
    option.Some(max_age) -> {
      let now = timestamp.system_time()
      let token_time = timestamp.from_unix_seconds(token_timestamp)
      let age = timestamp.difference(token_time, now)
      case duration.compare(age, max_age) {
        order.Gt -> Error(TokenExpired)
        order.Eq | order.Lt -> next()
      }
    }
  }
}
