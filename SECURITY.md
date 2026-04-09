# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.y   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

To report a security vulnerability, please use [GitHub Security Advisories](https://github.com/jtdowney/amaro/security/advisories/new).

**Please do not report security vulnerabilities through public GitHub issues.**

When reporting, include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

You can expect an initial response within 48 hours. We will work with you to understand the issue and coordinate disclosure.

## Security Model

amaro is a token encryption library providing [Fernet](https://github.com/fernet/spec) and [Branca](https://github.com/tuupola/branca-spec) token formats. It delegates all cryptographic primitives to [kryptos](https://github.com/jtdowney/kryptos), which in turn uses platform-native implementations:

- **Erlang target**: OTP `:crypto` and `:public_key` modules (OpenSSL/LibreSSL)
- **JavaScript target**: Node.js `crypto` module (OpenSSL)

amaro does not implement any cryptographic primitives itself. Security of the underlying operations depends on kryptos and the platform implementations being correct and up to date.

## Runtime Requirements

### Node.js

Use a currently supported Node runtime with up-to-date OpenSSL/LibreSSL.

### Erlang/OTP

Use a currently supported OTP version with up-to-date OpenSSL/LibreSSL.
