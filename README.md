# amaro

[![Package Version](https://img.shields.io/hexpm/v/amaro)](https://hex.pm/packages/amaro)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/amaro/)

Fernet and Branca token encryption for Gleam.

```sh
gleam add amaro
```

## Which to use

Prefer Branca for new deployments. Choose Fernet only when you need to inter-operate with existing systems.

Both libraries encrypt a `BitArray` payload, so encode your state into a `BitArray` before passing it to `encrypt`.

## Fernet

[Fernet](https://github.com/fernet/spec) tokens use AES-128-CBC with HMAC-SHA256. Tokens are base64url-encoded.

```gleam
import amaro/fernet

let key = fernet.generate_key()
let token = fernet.encrypt(key, plaintext: <<"too many secrets":utf8>>)
let assert Ok(plaintext) = fernet.decrypt(key, token:)
```

Enforce a maximum token age:

```gleam
import gleam/time/duration

let assert Ok(plaintext) =
  fernet.decrypt_with_ttl(key, token:, ttl: duration.seconds(60))
```

Keys serialize as base64url strings:

```gleam
let encoded = fernet.key_to_string(key)
let assert Ok(key) = fernet.key_from_string(encoded:)
```

## Branca

[Branca](https://github.com/tuupola/branca-spec) tokens use XChaCha20-Poly1305 authenticated encryption. Tokens are base62-encoded.

```gleam
import amaro/branca

let key = branca.generate_key()
let token = branca.encrypt(key, plaintext: <<"too many secrets":utf8>>)
let assert Ok(plaintext) = branca.decrypt(key, token:)
```

Enforce a maximum token age:

```gleam
import gleam/time/duration

let assert Ok(plaintext) =
  branca.decrypt_with_ttl(key, token:, ttl: duration.seconds(60))
```

Keys are raw 32-byte values:

```gleam
let bytes = branca.key_to_bytes(key)
let assert Ok(key) = branca.key_from_bytes(bytes:)
```
