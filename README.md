# php-totp

[![Conmposer Validation and Unit Tests](https://github.com/darrenedale/php-totp/actions/workflows/php-ci.yml/badge.svg)](https://github.com/darrenedale/php-totp/actions/workflows/php-ci.yml)

**Warning** This is pre-release software, the API has not yet stabilised.

Time-based One Time Password Generator for PHP

Add two-factor authentication to your app using TOTP and enable your users to use commonly-available authenticator apps
like Google Authenticator to secure their logins.

## Quick start

1. Generate a secure, random secret for your user: `Totp::randomSecret()`
2. Send a one-time notification to the user for them to import into their authenticator
   app: `UrlGenerator::for($user->username)->urlFor(new Totp($user->secret))`
3. When a user logs in, ask them for their current TOTP and verify it: `(new Totp($user->secret))->verify($inputOtp)`

## Introduction

The following sections use fictional functions, classes and methods to fill in the gaps for functionality that is
outside the scope of the php-totp library. For example, where the documentation references the `encrypt()` function it
is referring to whatever mechanism your app uses to encrypt data, not an actual `encrypt()` function. The examples also
assume a standard TOTP setup as described in [RFC 6238](https://www.ietf.org/rfc/rfc6238.txt) - that is, a reference
time of 00:00:00 on 01/01/1970, a time step of 30 seconds and the SHA1 producing 6-digit passwords. Possibilities for
customising the TOTP setup are described later.

## Provisioning Users

There are three steps involved in provisioning a user with TOTP:

1. Generate, encrypt and store a secret for the user.
2. Send them a notification with a URL, secret and/or QR code they can import into their authenticator app.
3. Verify successful provisioning by asking them for their current OTP.

### Generating secrets

The TOTP specification mandates that secrets are generated randomly (i.e. not chosen by the user). You can generate your
own secrets, but the `Totp` class provides a method that will generate a random secret for you that is guaranteed to be
cryptographically secure and strong enough to make the most of all the hashing algorithms supported by the TOTP
specification. This method is also used when instantiating `Totp` objects without providing an explicit secret.

Once you have generated the secret you must store it securely. Never store it unencrypted, and make sure you have a
strong key for your encryption. Use different keys for your various environments, and make sure you refresh your key
often.

```php
$user->totpSecret = encrypt(Totp::randomSecret());
$user->save();
```

Often, Base32 encoding is used with TOTP secrets, particularly when adding a new service to an authenticator app. If you
need your secret in Base32, `php-totp` provides a `Base32` codec class to help with the conversion:

```php
$user->totpSecret = encrypt(Base32::encode(Totp::randomSecret()));
$user->save();
```

Sometimes Base64 is also used. PHP provides Base64 encoding and decoding as standard, but for consistency php-totp also
provides a `Base64` codec class that operates identically to the Base32 class, except it works with Base64.

### Minimising the secret's unencrypted availability

You should strive to minimise the time that the shared secret is unencrypted in RAM, so you should only retrieve it just
before you are ready to verify it. Moreover, you should ensure that the variable containing the secret is overwritten
with random data before it goes out of scope, otherwise the unecrypted secret will remain "visible" in memory that is no
longer in use by your app. The `Totp::shred()` method is provided to simplify this - simply pass it the variable
containing the secret string and it will overwrite it with random bytes. The `Totp` class destructor uses this method to
scrub its record of the secret. The destuctor only does this once all references to the object have been discarded -
i.e. its reference count reaches 0 or the only remaining references are circular references in objects that are
themselves no longer accessible. You should therefore also strive to ensure that you don't keep unnecessary references
to your `Totp` objects.

### Notifying users

There are three common ways that user's are provided with the details of their TOTP secret and most authenticator apps
support at least one of them - many support all three.

**1. Sending the secret only**

The first is simply sending them the secret. Since the secret is a binary string, it will need to be converted to some
kind of plain-text safe format, and Base32 is usually used for this. This method of notifying users is only viable if
the standard TOTP setup is being used - that is 6-digit OTPs, SHA1 hashes, the Unix epoch as the reference time and 30
seconds as the time step. If you are using a custom TOTP setup, you will need to provide more information to your users,
and they will need to perform more steps to configure their authenticator app.

```php
$user->notify(Base32::encode(decrypt($user->totpSecret)));
```

**2. Sending an `otpauth` URL**

The second method is to send your users a specially constructed URL that their authenticator app can read to extract all
the information necessary to generate OTPs. The URL format is
[described here](https://github.com/google/google-authenticator/wiki/Key-Uri-Format). _php-totp_ provides a simple
mechanism for generating such URLs:

```php
$user->notify(UrlGenerator::from("MyWebApp")->for($user->username)->urlFor(new Totp(decrypt($user->totpSecret)));
```

By default, the UrlGenerator will insert as much information into the generated URL as is necessary to represent your
TOTP setup. So if you are using the SHA512 hash algorithm, the generated URL will contain the `algorithm` URL parameter
but if you're using the default SHA1 algorithm, the algorithm URL parameter will be omitted. The UrlGenerator class
provides a fluent interface to configure how it constructs the URLs (for example, you can force it to generate the
`algorithm` URL parameter regardless of whether you are using a non-default algorithm).

This method of notifying can cope with all custom setups except those that use a non-standard reference time (since
there is no URL parameter for providing it). Many TOTP-capable authenticator apps support URLs of this type, although
you will need to check the level of support in the app you are targeting for your users - for example
_Google Authenticator_ supports URLs but does not recognise the `algorithm` parameter and only supports the SHA1
algorithm.

**3. Sending a QR code**

The third method is to send users a specially constructed QR code that their authenticator app can scan to extract all
the information necessary to generate OTPs. This is effectively identical to using the URL method above - the QR code is
simply a representation of the generated URL.

_php-totp_ does not (yet) have a QR code generator, but it should be simple to use an existing QR code generator along
with the `UrlGenerator` to create QR codes to send to your users.
[_bacon/bacon-qr-code_](https://packagist.org/packages/bacon/bacon-qr-code) is one such external library.

### Verifying successful provisioning

Once a user has been provisioned, you need them to enter the OTP from their authenticator app to confirm that it has
been set up successfully. Once you've received the user's input, verification is simple:

```php
$isVerified = (new Totp(decrypt($user->totpSecret))->verify($userInput);
```

To avoid problems that can arise when the user enters their OTP when it's close to expiring (i.e. it's close to the end
of the time step), you can choose to accept a certain number of previous passwords as well as the current password. You
can do this by providing a `window` argument to the `Totp::verify()` method. The argument identifies how many time steps
the verification should go back to check for a matching OTP.

```php
$isVerified = (new Totp(decrypt($user->totpSecret))->verify(password: $inputOtp, window: 1);
```

By default, `Totp::verify()` will only accept the current OTP. **It is very strongly recommended that you verify _at
most_ with a window of 1 (i.e. accept either the current OTP or the one before it).**

## Authenticating

Authenticating users' TOTP is mostly a simple case of asking the user for their current OTP and verifying it. Obviously,
you must only do this alongside verification of their primary factor (e.g. their main password). This process is
identical to verifying the initial setup of their TOTP app:

```php
$isVerified = (new Totp(decrypt($user->totpSecret))->verify($userInput);
```

Or, with a window of verification:

```php
$isVerified = (new Totp(decrypt($user->totpSecret))->verify(password: $inputOtp, window: 1);
```

If `Totp::verify()` returns `false`, the user has not provided the correct OTP and must not be authenticated with your
app; if it returns `true` the user has provided a valid OTP and can be authenticated.

### Ensuring OTPs are used only once

The TOTP specification mandates that each generated OTP must be used only once to successfully authenticate. That is,
once an OTP has been used to successfully authenticate, that OTP may not be used again. This is one reason why it's
important to keep your time steps relatively short - if it's too long users may be effectively locked out for a short
period of time.

One way to ensure each OTP is used only once is to record the TOTP counter value after each successful authentication.
The counter is an incrementing integer value that indicates how many time steps have passed since the reference time for
the TOTP. By recording the highest used counter value you can check it against the counter value when a user attempts
to authenticate, and if the value is equal to or lower than the recorded counter the OTP has already been used and the
OTP cannot be used to authenticate again.

```php
$totp = new Totp(decrypt($user->totpSecret));

if ($user->highestUsedTotpCounter < $totp->counter()) {
    if ($totp->verify($inputOtp)) {
       $user->highestUsedTotpCounter = $totp->counter();
       $user->save();
       // user is authenticated
    } else {
        // incorrect OTP
    }
} else {
    // OTP has already been used
}

// ensure the secret is shredded
unset($totp);
```

You can also use a verification window in the call to `Totp::verify()`, but don't forget to adjust the window to avoid
accepting a previously-used OTP:

```php
$totp = new Totp(decrypt($user->totpSecret));
$window = min(1, $totp->counter() - $user->highestUsedTotpCounter - 1);

if (0 <= $window) {
    if ($totp->verify(password: $inputOtp, window: $window)) {
        ...
    }
}

// ensure the secret is shredded
unset($totp);
```

## Custom TOTP configurations

There are four things you can customise about your TOTP setup:

1. The hashing algorithm
2. The reference timestamp
3. The size of the time step
4. The number of digits in your OTPs

Customising your TOTP setup should be considered a one-time option. Once you have settled on a setup it is difficult
to change it (you'd need to re-provision all your users and they would all need to reconfigure their authenticator apps)
so it's usually best to choose your setup wisely at the start.

Both the `Totp` constructor and the convenience factory methods `Totp::sixDigits()`, `Totp::eightDigits()` and
`Totp::integer()` use the defaults specified in the TOTP RFC for the default arguments, which means you can use named
arguments to customise only those aspects of your TOTP instances that are non-default.

### Hashing algorithms

TOTP supports three hashing algorithms - SHA1, SHA256 and SHA512. The strongest is SHA512, while the default specified
in the RFC is SHA1 (for compatibility with HOTP). As noted above, you should check that the authenticator apps that you
are targeting for your users support the algorithm you are intending to use before customising it.

The `Totp` class provides constants representing all supported hashing algorithms, and you are strongly encouraged to
use these to avoid exceptions in your app. Using the constants protects your code against changes to the underlying
values that are used to represent the algorithms, and will provide you with a pain-free upgrade path for your app
if/when the code is updated to use PHP8.1 enumerations for hash algorithms.

To use SHA256 create all your `Totp` instances like this:

```php
// when provisioning
$totp = new Totp(hashAlgorithm: Totp::Sha256Algorithm);
// when verifying
$totp = new Totp(secret: decrypt($user->totpSecret), hashAlgorithm: Totp::Sha256Algorithm);
```

Similarly, to use SHA512:

```php
// when provisioning
$totp = new Totp(hashAlgorithm: Totp::Sha512Algorithm);
// when verifying
$totp = new Totp(secret: decrypt($user->totpSecret), hashAlgorithm: Totp::Sha512Algorithm);
```

### Reference timestamp and time step

TOTP works by calculating a counter value that is the number of time steps of a given size that have elapsed since a
given point in time. By default, the point in time is 00:00:00 01/01/1970 (AKA the Unix epoch), which is 0 when
represented as a Unix timestamp. The time step default is 30 seconds. Unless you have a good reason to deviate from
them, the default reference time and time step are reasonable choices. If you do choose to customise the time step, bear
in mind that very small intervals will make it harder for users since they'll have less time available to enter the
correct OTP. Similarly, making the interval too large can also make it difficult for users since they may have to wait
for a time step to expire to log in again (each OTP must only be used to authenticate once, so if a user logs in then
immediately logs out, with a time step of 10 minutes, say, the user won't be able to log in againt for another 9 minutes
or so).

The reference timestamp and time step can be customised on their own - that is, you can customise the reference
timestamp without customising the time step and vice versa.

### Password digits

The number of digits in your OTPs defaults to 6, but can range from 6 to 9 inclusive. There's technically no reason why
larger numbers of digits can't be used, but owing to the internal mechanism by which the password is generated there is
nothing to gain since the number from which it is derived has at most 9 digits, so any more digits will just result in
padding with 0s to the left.

Note that there are schemes available for generating OTPs that are not just 6-9 numeric digits - see the Steam renderer,
for example, which produces 4-character passcodes compatible with the Steam authenticator. In most cases, however,
you'll probably want to stick with 6-9 digit OTPs.

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