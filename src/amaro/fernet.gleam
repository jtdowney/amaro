//// Encrypt and decrypt [Fernet](https://github.com/fernet/spec) tokens.
////
//// Fernet tokens are authenticated and encrypted using AES-128-CBC and
//// HMAC-SHA256. Tokens are base64url-encoded and safe for use in URLs,
//// headers, and cookies.
////
//// ## Example
////
//// ```gleam
//// let key = fernet.generate_key()
//// let token = fernet.encrypt(key, plaintext: <<"hello":utf8>>)
//// let assert Ok(plaintext) = fernet.decrypt(key, token:)
//// ```

import gleam/bit_array
import gleam/bool
import gleam/option.{type Option}
import gleam/order
import gleam/result
import gleam/time/duration.{type Duration}
import gleam/time/timestamp.{type Timestamp}
import kryptos/block
import kryptos/crypto
import kryptos/hash
import kryptos/hmac

const version = 0x80

const key_size = 32

const signing_key_size = 16

const iv_size = 16

const tag_size = 32

const min_token_size = 73

/// A 256-bit Fernet key containing a 128-bit signing key and a 128-bit
/// encryption key. Generate one with `generate_key` or decode an existing
/// one with `key_from_string`.
pub opaque type Key {
  Key(data: BitArray)
}

/// Errors that can occur during key parsing or token operations.
pub type Error {
  /// Key is not 32 bytes or not valid base64url.
  InvalidKey
  /// Token is not valid base64url or is too short to contain all fields.
  InvalidToken
  /// Token version byte is not 0x80.
  InvalidVersion
  /// HMAC verification failed. The token was tampered with or the wrong
  /// key was used.
  InvalidSignature
  /// Token age exceeds the TTL passed to `decrypt_with_ttl`.
  TokenExpired
  /// AES-CBC decryption or PKCS#7 unpadding failed.
  DecryptionFailed
}

/// Generate a random Fernet key using a cryptographically secure RNG.
pub fn generate_key() -> Key {
  Key(crypto.random_bytes(key_size))
}

/// Decode a key from a base64url-encoded string. Returns `InvalidKey` if the
/// string is not valid base64url or does not decode to exactly 32 bytes.
pub fn key_from_string(encoded encoded: String) -> Result(Key, Error) {
  case bit_array.base64_url_decode(encoded) {
    Ok(<<data:bytes-size(key_size)>>) -> Ok(Key(data))
    _ -> Error(InvalidKey)
  }
}

/// Encode a key as a base64url string with padding.
pub fn key_to_string(key: Key) -> String {
  bit_array.base64_url_encode(key.data, True)
}

/// Encrypt plaintext into a Fernet token string. The current system time is
/// recorded in the token and a random IV is generated for each call.
pub fn encrypt(key: Key, plaintext plaintext: BitArray) -> String {
  let now = timestamp.system_time()
  let iv = crypto.random_bytes(iv_size)
  let assert Ok(token) = encrypt_with(key, plaintext:, now:, iv:)
  token
}

@internal
pub fn encrypt_with(
  key: Key,
  plaintext plaintext: BitArray,
  now now: Timestamp,
  iv iv: BitArray,
) -> Result(String, Error) {
  let #(signing_key, encryption_key) = split_key(key)
  let #(seconds, _nanoseconds) = timestamp.to_unix_seconds_and_nanoseconds(now)

  use cipher <- result.try(
    block.aes_128(encryption_key)
    |> result.replace_error(InvalidKey),
  )
  use ctx <- result.try(
    block.cbc(cipher, iv:)
    |> result.replace_error(InvalidToken),
  )
  use ciphertext <- result.try(
    block.encrypt(ctx, plaintext)
    |> result.replace_error(DecryptionFailed),
  )

  let payload = <<
    version,
    seconds:big-size(64),
    iv:bits,
    ciphertext:bits,
  >>

  use h <- result.try(
    hmac.new(hash.Sha256, signing_key)
    |> result.replace_error(InvalidSignature),
  )
  let mac = h |> hmac.update(payload) |> hmac.final()

  Ok(bit_array.base64_url_encode(<<payload:bits, mac:bits>>, True))
}

/// Decrypt a Fernet token and return the original plaintext. The token's HMAC
/// is verified before decryption. No expiry check is performed.
pub fn decrypt(key: Key, token token: String) -> Result(BitArray, Error) {
  do_decrypt(key, token, option.None)
}

/// Decrypt a Fernet token, rejecting it if its age exceeds `ttl`. Age is
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
    bit_array.base64_url_decode(token)
    |> result.replace_error(InvalidToken),
  )

  use #(token_version, token_timestamp, iv, ciphertext, tag) <- result.try(
    parse_token(data),
  )

  use <- guard_version(token_version)
  use <- guard_ttl(token_timestamp, ttl)

  let #(signing_key, encryption_key) = split_key(key)

  let payload_size = bit_array.byte_size(data) - tag_size
  use payload <- result.try(
    bit_array.slice(data, 0, payload_size)
    |> result.replace_error(InvalidToken),
  )

  use <- guard_tag(signing_key, payload, tag)

  use cipher <- result.try(
    block.aes_128(encryption_key)
    |> result.replace_error(DecryptionFailed),
  )
  use ctx <- result.try(
    block.cbc(cipher, iv:)
    |> result.replace_error(DecryptionFailed),
  )
  block.decrypt(ctx, ciphertext)
  |> result.replace_error(DecryptionFailed)
}

fn parse_token(
  data: BitArray,
) -> Result(#(Int, Int, BitArray, BitArray, BitArray), Error) {
  use <- bool.guard(
    when: bit_array.byte_size(data) < min_token_size,
    return: Error(InvalidToken),
  )
  let ciphertext_size = bit_array.byte_size(data) - 1 - 8 - iv_size - tag_size
  case data {
    <<
      version:int,
      timestamp:big-size(64),
      iv:bytes-size(iv_size),
      ciphertext:bytes-size(ciphertext_size),
      tag:bytes-size(tag_size),
    >> -> Ok(#(version, timestamp, iv, ciphertext, tag))
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

fn split_key(key: Key) -> #(BitArray, BitArray) {
  let assert Ok(signing_key) = bit_array.slice(key.data, 0, signing_key_size)
  let assert Ok(encryption_key) =
    bit_array.slice(key.data, signing_key_size, signing_key_size)
  #(signing_key, encryption_key)
}

fn guard_tag(
  signing_key: BitArray,
  payload: BitArray,
  expected: BitArray,
  next: fn() -> Result(BitArray, Error),
) -> Result(BitArray, Error) {
  case hmac.verify(hash.Sha256, key: signing_key, data: payload, expected:) {
    Ok(True) -> next()
    Ok(False) | Error(Nil) -> Error(InvalidSignature)
  }
}
