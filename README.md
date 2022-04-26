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

### Provisioning a user

Provision a user with TOTP and send them a notification with a URL they can import into their authenticator app.

````php
// get hold of your user object in whatever way you normally do it
$user = get_user();
$totp = new Totp(algorithm: Totp::Sha512Algorithm);
$user->setTotpSecret($totp->secret());
$user->notify(\Equit\Totp\UrlGenerator::for($user->userName())->from("Equit")->urlFor($totp));
unset($totp);     // ensure the secret is wiped from memory
````

### Provisioning multiple users

Provision multiple users with TOTP and send each a notification with a URL they can import into their authenticator app.

````php
$generator = \Equit\Totp\UrlGenerator::from("Equit");

// get hold of your user objects in whatever way you need
foreach (get_users() as $user) {
   $totp = new Totp(algorithm: Totp::Sha512Algorithm);
   $user->setTotpSecret($totp->secret());
   $user->notify($generator->for($user->userName())->urlFor($totp));
}
````

### Authenticating

````php
// get hold of your user object in whatever way you normally do it
$user = get_user();
$totp = Equit\Totp\Totp::sixDigits(secret: $user->totpSecret());

if ($totp->verify(password: $_POST["totp"], window: 1)) {
    // user is authenticated
} else {
    // user is not authenticated
}

$totp->setSecret(random_bytes(20));
$totp = null;
````

## Generating secure secrets

The TOTP specification mandates that secrets are generated randomly (i.e. not chosen by the user). The Totp class will
generate a cryptographically-secure random secret if none is provided to the constructor (or one of the factory methods 
if that's how you're instantiating your Totp). Such internally-generated secrets will be 64 bytes (512 bits) in length
and are sufficiently strong for all configurations of Totp. If you want to generate your own random secrets when
provisioning TOTP for your users, read on. If you're happy to let the Totp class do this for you, you need not read this
section.

To generate good secrets for your users you need a good source of random data. PHP's `random_bytes()` function is a
suitable source. If this is not available on your platform you'll need to look elsewhere. PHP's other random number
generation functions are not necessarily good sources of cryptographically secure randomness.

The HOTP algorithm which is used by TOTP, uses SHA1 HMACs under the hood when generating one-time passwords. Keys for
this type of HMAC are limited to 160 bits as per [RFC 2104](https://www.ietf.org/rfc/rfc2104.txt):

> The authentication key K can be of any length up to B, the block length of the hash function. **Applications that use
> keys longer than B bytes will first hash the key using H [the hashing algorithm]** and then use the resultant L
> [the byte length of the computed hash] byte string as the actual key to HMAC.

The absolute minimum size for a shared secret, according to [RFC 4226](https://www.ietf.org/rfc/rfc4226.txt) (the HOTP
specification) is 128 bits (16 bytes):

> R6 - The algorithm MUST use a strong shared secret.  **The length of the shared secret MUST be at least 128 bits.**
> This document RECOMMENDs a shared secret length of 160 bits.

The TOTP specification allows for the use of SHA256 or SHA512 algorithms, while using SHA1 by default. Since it depends
on HOTP, HOTP uses HMACs, and HMACs reduce any key longer than the digest produced by the hashing algorithm to the
length of the digest by hashing it, there is little value in providing a secret longer than the digest size of the
algorithm in use. HOTP recommends 160 bits on the basis of the SHA1 algorithm's digests being of that length; if you are
using SHA256 or SHA512 algorithms with your TOTPs, that recommendation should probably increase to the length of their
digests - 256 bits (32 bytes) for SHA256 and 512 bits (64 bytes) for SHA512.

Totp's internal random secret generator always generates 512 bit secrets. While this produces little extra benefit over
160 bits if the algorithm is SHA1 (256 bits if it's SHA256), the only downside is an undetectable performance cost. If
you are providing your own random secrets, the following would be good ways to generate them:

| Algorithm | Random secret generator |
|-----------|-------------------------|
| SHA1      | `random_bytes(20)`      |
| SHA256    | `random_bytes(32)`      |
| SHA512    | `random_bytes(64)`      |

Once you have generated the secret you must store it securely. Never store it unencrypted, and make sure you have a
strong key for your encryption. Use different keys for your various environments, and make sure you refresh your key
often.

Most authenticator apps can scan QR codes or allow the user to enter the shared secret as text. The secrets themselves
are binary data - a byte sequence not a string. As such, in their raw form they are not easy for users to type into
their authenticator app. Base32 is usually used for this purpose in TOTP. Whether you store your users' secrets as raw
bytes or Base32 encoded, you still need to encrypt the stored secret.

## Authenticating

Once you have received the OTP the user has input, you need to compare it to the generated OTP. This involves the
following logical steps:

1. Retrieve the shared secret for the appropriate user from your storage.
2. Decrypt the shared secret.
3. Use the shared secret to generate the expected OTP.
4. Compare the expeted OTP to the OTP provided by the user.

There are two primary security concerns with authenticating using TOTP:

1. Ensuring that the shared secret remains decrypted for the shortest time possible.
2. Ensuring that each OTP generated is only used to authenticate once.

### Minimising the secret's unencrypted availability

You should strive to minimise the time that the shared secret is unencrypted in RAM, so you should only retrieve it just
before you are ready to compare it to the user's input and you should unset the variable as soon as you have
done the comparison. The Totp class destructor will overwrite the contents of the unencrypted secret with random data so
that after the object's memory has been freed it no longer contains the unencrypted secret. The destuctor only does its
work once all references to the object have been discarded - i.e. its reference count reaches 0 or the only remaining
references are circular references in objects that are themselves no longer accessible. You should therefore also strive
to ensure that you don't keep unnecessary references to your Totp objects.

### Ensuring generated OTPs are only used once

The simplest way to ensure that each OTP is only used for at most one successful authentication attempt is to record the
timestamp or counter of the most recently used successful OTP. When the user attempts to authenticate, if the `Totp`
object's current timestamp/counter is equal to or lower than the last recorded successful authentication attempt then
the OTP is considered stale and must not be used to authenticate.

It is important that you ensure that all routes to authentication that use the TOTP secret are protected in this way -
for example if you have a mobile app and a web app, you must ensure that a OTP used to authenticate with the web app
cannot subsequently be used to authenticate using the mobile app. [RFC 4226](https://www.ietf.org/rfc/rfc4226.txt) has a
good discussion of the reasoning for this.

## References
- H. Krawczyk, M. Bellare & R. Canetti, _[RFC2104: HMAC: Keyed-Hashing for Message Authentication](https://www.ietf.org/rfc/rfc2104.txt)_, https://www.ietf.org/rfc/rfc2104.txt, retrieved 17th April, 2022.
- D. M'Raihi, M. Bellare, F. Hoornaert, D. Naccache & O. Ranen, 2005, _[RFC4226: HOTP: An HMAC-Based One-Time Password Algorithm](https://www.ietf.org/rfc/rfc4226.txt)_, https://www.ietf.org/rfc/rfc4226.txt, retrieved 17th April, 2022.
- D. M'Raihi, S. Machani, M. Pei & J. Rydell, 2011, _[RFC6238: TOTP: Time-Based One-Time Password Algorithm](https://www.ietf.org/rfc/rfc6238.txt)_, https://www.ietf.org/rfc/rfc6238.txt, retrieved 17th April, 2022.