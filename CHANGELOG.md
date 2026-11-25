# Changelog

All notable changes to `neotales-age` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.0-alpha.2] - 2026-11-25

### Security

- Hardened `PluginRecipient` and `PluginIdentity` to store encoded plugin strings in `Zeroizing<String>` and redact `encoding` as `"[REDACTED]"` in `fmt::Debug`.
- Added `ChildGuard` in plugin client connections so spawned plugin processes are terminated and reaped on drop across every exit path.
- Updated `plugin_response_error` to return a non-reflecting protocol error instead of echoing raw plugin response text into `AgeError`.
- Migrated from `rsa` `0.9.10` + `sad-rsa` `0.10.2` to `rsa` `0.10.0` with blinded OAEP decryption, eliminating `RUSTSEC-2023-0071` and removing the advisory ignore from `deny.toml` and `.github/workflows/audit.yml`.
- Updated `zeroize` pin from `=1.9.0` to `=1.9.1`.

### Changed

- Updated `neotales-x509` dependency from `0.0.0-alpha.1` to `0.0.0-alpha.2`.
- Updated `AgeIdentity::from_ssh_rsa_private_key` and internal RSA key types from `rsa` `0.9.10` (`RsaPrivateKey` / `RsaPublicKey`) to `rsa` `0.10.0` (`rsa::PrivateKey` / `rsa::PublicKey`).

### Fixed

- Fixed plugin stanza body parsing (`read_stanza`) to terminate the body after a short (`< 64`-character) line without consuming a following empty line, and to reject body lines longer than 64 characters.
- Added wide-prime (unbalanced) RSA private-key import compatibility across PKCS#1, PKCS#8, OpenSSH, and legacy encrypted PEM formats, backed by `tests/data/rsa-unbalanced-*` fixtures and `tests/rsa_unbalanced.rs`.

## [0.0.0-alpha.1] - 2026-11-20

### Added

- Initial standalone prerelease of `neotales-age`.
- Added native X25519 and post-quantum ML-KEM-768 + X25519 hybrid keys, encryption-only tagged P-256 and ML-KEM-768 + P-256 recipients, scrypt passphrases, and SSH Ed25519 and RSA key support (`AgeFile`, `AgeKey`, `AgeRecipient`, `AgeIdentity`).
- Added streaming STREAM encryption/decryption and strict ASCII armor (`AgeArmor`, `streaming`).
- Added age v1 plugin client/host protocol support (`Plugin`, `PluginRecipient`, `PluginIdentity`, `ClientUi`) and Bech32 helpers (`bech32`).
- Added CI (`fmt`, `clippy`, tests, doctests, `rustdoc`, MSRV `1.100`), `cargo-deny` / `cargo-audit`, and OIDC trusted-publishing release workflows.
