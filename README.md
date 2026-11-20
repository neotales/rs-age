# neotales-age

age v1 file encryption in Rust: native and post-quantum recipients, passphrases,
SSH keys, and ASCII armor.

[![Neotales](https://github.com/neotales/brand/raw/main/assets/logo.png)](https://github.com/neotales/rs-age)

<!-- badges: crates.io, docs.rs, CI. Add once the crate name and first version exist. -->

## Install

```sh
cargo add neotales-age
```

## What you can do 🔐

**Encrypt to a public key.** A recipient writes. The matching identity reads.
The two halves are separate values, so the public half can be handed out on its own.

```rust
use neotales_age::{AgeFile, AgeIdentity, AgeKey, AgeRecipient};

let key = AgeKey::generate()?;
let recipient = AgeRecipient::from_public_key(&key.public_key)?;
let identity = AgeIdentity::from_private_key(&key.private_key)?;

let encrypted = AgeFile::encrypt(b"a message", &[recipient])?;
assert_eq!(AgeFile::decrypt(&encrypted, &[identity])?, b"a message");
# Ok::<(), neotales_age::Error>(())
```

**Encrypt to several people at once.** Pass one slice and every recipient gets a
stanza in the same header.

```rust
use neotales_age::{AgeFile, AgeIdentity, AgeKey, AgeRecipient};

let alice = AgeKey::generate()?;
let bob = AgeKey::generate()?;
let recipients: Vec<AgeRecipient> = [&alice, &bob]
    .into_iter()
    .map(|key| AgeRecipient::from_public_key(&key.public_key))
    .collect::<Result<_, _>>()?;

let encrypted = AgeFile::encrypt(b"for both of you", &recipients)?;
let bob_identity = AgeIdentity::from_private_key(&bob.private_key)?;
assert_eq!(AgeFile::decrypt(&encrypted, &[bob_identity])?, b"for both of you");
# Ok::<(), neotales_age::Error>(())
```

**Send armor through text.** `encrypt_armored` returns the strict ASCII form, and
`decrypt_armored` accepts it back.

```rust
use neotales_age::{AgeFile, AgeIdentity, AgeKey, AgeRecipient};

let key = AgeKey::generate()?;
let recipient = AgeRecipient::from_public_key(&key.public_key)?;
let identity = AgeIdentity::from_private_key(&key.private_key)?;

let armored = AgeFile::encrypt_armored(b"copy me", &[recipient])?;
assert!(armored.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
assert_eq!(AgeFile::decrypt_armored(&armored, &[identity])?, b"copy me");
# Ok::<(), neotales_age::Error>(())
```

**Reuse an SSH key.** `AgeRecipient::from_ssh_public_key` and
`AgeIdentity::from_ssh_private_key` take the OpenSSH text form for Ed25519 and
RSA keys.

**Stretch a passphrase with scrypt.** `AgeRecipient::from_passphrase` and
`AgeIdentity::from_passphrase` take the passphrase. The work factor is written
into the header, so decryption reproduces it.

## Licence

[MIT](LICENSE.md)
