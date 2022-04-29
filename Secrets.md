# Generating your own secure secrets

The `Totp` class can generate secrets that are as cryptographically strong as is possible for all hash algorithms
supported by TOTP. However, if you can't or don't want to use this method, this document describes how to generate
strong secrets.

To generate good secrets for your users you need a good source of random data. PHP's `random_bytes()` function is a
suitable source. If this is not available on your platform you'll need to look elsewhere. PHP's other random number
generation functions are not necessarily good sources of cryptographically secure randomness.

TOTP builds on HOTP, which uses HMACs, whose [RFC](https://www.ietf.org/rfc/rfc2104.txt) has this to say about the size
of keys:

> The authentication key K can be of any length up to B, the block length of the hash function. **Applications that use
> keys longer than B bytes will first hash the key using H [the hashing algorithm]** and then use the resultant L
> [the byte length of the computed hash] byte string as the actual key to HMAC.

In other words, if you create a secret that is longer than the bit length of the digest that the hashing algorithm uses,
it will first be hashed before being used, reducing it to the length of the digest. For TOTP this means there is little
benefit in providing secrets longer than 160 bits (20 bytes) for SHA1, 256 bits (32 bytes) for SHA256 or 160 bits (64
bytes) for SHA512.

The absolute minimum size for a shared secret, according to the HOTP [RFC](https://www.ietf.org/rfc/rfc4226.txt) is 128
bits (16 bytes):

> R6 - The algorithm MUST use a strong shared secret.  **The length of the shared secret MUST be at least 128 bits.**
> This document RECOMMENDs a shared secret length of 160 bits.

The recommendation of 160 bits for shared secrets is based on HOTP using SHA1, whose digest length is 160 bits. For
TOTP, since it can use SHA256 or SHA512, this recommendation should increase to the digest lengths for the appropriate
algorihm - 256 bits for SHA256 or 512 bits for SHA512. Therefore, if you are providing your own random secrets, the
following would be good ways to generate them:

| Algorithm | Random secret generator |
|-----------|-------------------------|
| SHA1      | `random_bytes(20)`      |
| SHA256    | `random_bytes(32)`      |
| SHA512    | `random_bytes(64)`      |
