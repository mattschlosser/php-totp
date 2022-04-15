# php-totp

**Warning** This is pre-release software, the API has not yet stabilised.

Time-based One Time Password Generator for PHP

Add two-factor authentication to your app using TOTP and enable your users to use
commonly-available authenticator apps like Google Authenticator to secure their
logins.

## Quick start

1. Generate a secure, random secret for your user and have them import it into their
   authenticator
2. When a user logs in, ask them for their current TOTP
3. Instantiate an `Equit\Totp\Totp` and tell it the user's secret
4. Compare the user's input to the return value from the Totp instance's `currentPassword()`
   method. If they're the same, the user is authenticated.

## Pseudo-code examples

### Generating a secret
````php
// get hold of your user object in whatever way you normally do it
$user = get_user();
$secret = random_bytes(20);
$user->setTotpSecret($secret);
// show secret to user, just this once, so they can import it into their authetnicator app
````

### Authenticating
````php
// get hold of your user object in whatever way you normally do it
$user = get_user();
$inputPassword = $_POST["totp"];
$totp = Equit\Totp\Totp::sixDigitTotp($user->totpSecret());

if ($totp->currentPassword() === $inputPassword) {
    // user is authenticated
} else {
    // user is not authenticated
}
````

## Generating secure secrets

To generate good secrets for your users you need a good source of random data. PHP's `random_bytes()` function is a suitable source. If this is not available on your platform you'll need to look elsewhere. PHP's other random number generation functions are not necessarily good sources of cryptographically secure randomness.

The TOTP algorithm uses SHA1 HMACs under the hood when generating one-time passwords, whose keys are limited to 160 bits as per [RFC 2104](https://www.ietf.org/rfc/rfc2104.txt), the HMAC specification:

> The authentication key K can be of any length up to B, the block length of the hash function. Applications that use keys longer than B bytes will first hash the key using H [the hashing algorithm] and then use the resultant L [the byte length of the computed hash] byte string as the actual key to HMAC.

The absolute minimum size for a shared secret, according to [RFC 4226](https://www.ietf.org/rfc/rfc4226.txt), the HOTP specification on which TOTP is based, is 128 bits (16 bytes):

> R6 - The algorithm MUST use a strong shared secret.  The length of the shared secret MUST be at least 128 bits. This document RECOMMENDs a shared secret length of 160 bits.

Since SHA1 HMACs can use at most 160 bits in a shared secret, and since this provides siginficantly more protection against brute-force attacks, you should probably go for 160-bit secrets generated using a cryptographically-secure random generator. 160 bits is 20 octets (bytes), so `random_bytes(20)` is a good option for a sufficiently secure secret. There is little to be gained in generating secrets of more than 160 bits.

Once you have generated the secret you must store it securely. Never store it unencrypted, and make sure you have a strong key for your encryption. Use different keys for your various environments, and make sure you refresh your key often.

Most authenticator apps can scan QR codes or allow the user to enter the shared secret as text. The secrets themselves are binary data - a byte sequence not a string. As such, in their raw form they are not easy for users to type into their authenticator app. Base32 is usually used for this purpose in TOTP. Whether you store your users' secrets as raw bytes or Base32 encoded, you still need to encrypt the stored secret.
