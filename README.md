# php-totp

[![Conmposer Validation and Unit Tests](https://github.com/darrenedale/php-totp/actions/workflows/php-ci.yml/badge.svg)](https://github.com/darrenedale/php-totp/actions/workflows/php-ci.yml)

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
4. Pass the user's input to `Totp::verify()` - if it returns `true`, the user is authenticated.

## Examples

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
$totp = Equit\Totp\Totp::sixDigitTotp(secret: $user->totpSecret());

if ($totp->verify(password: $_POST["totp"], window: 1)) {
    // user is authenticated
} else {
    // user is not authenticated
}

$totp->setSecret(random_bytes(20));
$totp = null;
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

## Authenticating

Once you have received the OTP the user has input, you need to compare it to the generated OTP. This involves the following logical steps:

1. Retrieve the shared secret for the appropriate user from your storage.
2. Decrypt the shared secret.
3. Use the shared secret to generate the expected OTP.
4. Compare the expeted OTP to the OTP provided by the user.

There are two primary security concerns with authenticating using TOTP:

1. Ensuring that the shared secret remains decrypted for the shortest time possible.
2. Ensuring that each OTP generated is only used to authenticate once.

### Minimising the secret's unencrypted availability

You should strive to minimise the time that the shared secret is unencrypted in RAM, so you should only retrieve it just before you are ready to compare it to the user's input and you should overwrite the variable's RAM as soon as you have done the comparison. Practically, this means you should set the secret in the `Totp` object to a random byte sequence at least as long as the secret as soon as you have done the comparison. This is necessary because PHP does not specify precisely when an object is destroyed, only that it is garbage collected at some point after it goes out of scope. So when the Totp object is no longer in scope, the unencrypted secret still resides in RAM for an indeterminate period of time.

To do this, first call `setSecret(random_bytes(20))` on your `Totp` object (use whatever equivalent of `random_bytes()` you're using to generate secrets if `random_bytes()` is not available on your platform). This will overwrite the stored secret in the `Totp` object with random data. Then set the `Totp` object to `null` so that it gets garbage collected as soon as possible.

### Ensuring generated OTPs are only used once

The simplest way to ensure that each OTP is only used for at most one successful authentication attempt is to record the timestamp or counter of the most recently used successful OTP. When the user attempts to authenticate, if the `Totp` object's current timestamp/counter is equal to or lower than the last recorded successful authentication attempt then the OTP is considered stale and must not be used to authenticate.

It is important that you ensure that all routes to authentication that use the TOTP secret are protected in this way - for example if you have a mobile app and a web app, you must ensure that a OTP used to authenticate with the web app cannot subsequently be used to authenticate using the mobile app. [RFC 4226](https://www.ietf.org/rfc/rfc4226.txt) has a good discussion of the reasoning for this.

## References
- H. Krawczyk, M. Bellare & R. Canetti, _[RFC2104: HMAC: Keyed-Hashing for Message Authentication](https://www.ietf.org/rfc/rfc2104.txt)_, https://www.ietf.org/rfc/rfc2104.txt, retrieved 17th April, 2022.
- D. M'Raihi, M. Bellare, F. Hoornaert, D. Naccache & O. Ranen, 2005, _[RFC4226: HOTP: An HMAC-Based One-Time Password Algorithm](https://www.ietf.org/rfc/rfc4226.txt)_, https://www.ietf.org/rfc/rfc4226.txt, retrieved 17th April, 2022.
- D. M'Raihi, S. Machani, M. Pei & J. Rydell, 2011, _[RFC6238: TOTP: Time-Based One-Time Password Algorithm](https://www.ietf.org/rfc/rfc6238.txt)_, https://www.ietf.org/rfc/rfc6238.txt, retrieved 17th April, 2022.