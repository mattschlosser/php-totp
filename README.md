# php-totp

[![Conmposer Validation and Unit Tests](https://github.com/darrenedale/php-totp/actions/workflows/php-ci.yml/badge.svg)](https://github.com/darrenedale/php-totp/actions/workflows/php-ci.yml)

**Warning** This is pre-release software, the API has not yet stabilised.

Time-based One Time Password Generator for PHP

Add two-factor authentication to your app using TOTP and enable your users to use commonly-available authenticator apps
like Google Authenticator to secure their logins.

## Quick start

1. Generate a secure, random secret for your user:

```php
Totp::randomSecret()
```

2. Send a one-time notification to the user for them to import into their authenticator app:

```php
UrlGenerator::for($user->username)->urlFor(new Totp($user->secret))
```

3. When a user logs in, ask them for their current TOTP and verify it:

```php
(new Totp($user->secret))->verify($inputOtp)
```

## Introduction

TOTP is specified in [RFC 6238](https://www.ietf.org/rfc/rfc6238.txt) and builds on
[HMAC-based One-Time Passwords (HOTP, RFC4226)](https://www.ietf.org/rfc/rfc4226.txt) by computing a
[Hashed Message Authentication Code (HMAC, RFC 2104)](https://www.ietf.org/rfc/rfc2104.txt) based on a count of the
number of time periods that have elapsed since a given point in time and a random secret that is known by the
authorising server (your app) and a secure client app (your users' authenticator apps). A number between 0 and
2,147,483,647 is then derived from the HMAC and the rightmost 6 (usually) digits are used as the password (padded with
0s if required). As long as the server and app agree on the current time, the reference time, the size of the time
period and the secret, they both calculate the same sequence of passwords at the same time, enabling the server to
verify the user's authenticity. It is very unlikely that different combinations of secret, reference time and interval
will produce the same password at the same time.

_php-totp_  consists of three main components: a `Totp` class, which does most of the heavy lifting to calculate TOTPs;
an `UrlGenerator` class, which helps generate the information the user needs to set up their authenticator app;
and a collection of OTP `Renderer` classes that turn the calculation performed by `Totp` into actual one-time passwords.
(The latter classes are used internally by `Totp` and unless you are inventing your own scheme for creating passwords -
which is very strongly **not** recommended - you are very unlikely to have to use them.)

The following examples use notional functions, classes and methods to fill in the functionality gaps that are outside
the scope of the _php-totp_ library. For example, is uses an `encrypt()` function as a placeholder for whatever
mechanism your app uses to encrypt data. They also assume a standard TOTP setup as described in RFC 6238 - that is, a
reference time of 00:00:00 on 01/01/1970, a time step of 30 seconds and the SHA1 hashing algorithm producing 6-digit
passwords. Possibilities for customising the TOTP setup are described later.

## Provisioning TOTP for Users

There are three steps involved in provisioning a user with TOTP:

1. Generate, encrypt and store a secret for the user.
2. Send them a notification with a URL, secret and/or QR code they can import into their authenticator app.
3. Verify successful provisioning by asking them for their current OTP.

### Generating secrets

The TOTP specification mandates that secrets are generated randomly (i.e. not chosen by the user). You can generate your
own secrets, but the `Totp` class provides a method that will generate a random secret for you that is guaranteed to be
cryptographically secure and strong enough for all the hashing algorithms supported by TOTP. This method is also used
when instantiating `Totp` objects without providing an explicit secret.

Once you have generated the secret you must store it securely. It must always be stored encrypted.

```php
$user->totpSecret = encrypt(Totp::randomSecret());
$user->save();
```

Often, Base32 encoding is used with TOTP secrets, particularly when adding them to an authenticator app. If you need
your secret in Base32, _php-totp_ provides a `Base32` codec class to do the conversion:

```php
$user->totpSecret = encrypt(Base32::encode(Totp::randomSecret()));
$user->save();
```

Sometimes Base64 is also used. PHP provides built-in Base64 encoding and decoding, but for consistency _php-totp_ also
provides a `Base64` codec class that operates identically to the `Base32` class, except it works with Base64.

### Minimising the secret's unencrypted availability

You should strive to minimise the time that the shared secret is unencrypted in RAM. Whenever you are using it, whether
to provision or to verify, you should only retrieve it just before you are ready to use it, you should discard it as
soon as you no longer need it, and you should ensure that the variable containing the securely erased before it is
discarded. If you don't do this the unecrypted secret will remain "visible" in memory that is no
longer in use by your app. The `Totp::shred()` method is provided to simplify this - simply pass it the variable
containing the secret and it will overwrite it with random bytes.

Since `Totp` instances contain the secret, you must also ensure you keep your `Totp` instances no longer than necessary.
The `Totp` destructor will scrub its record of the secret so as long as you `unset()` your `Totp` variables once you no
longer need them the secrets should be securely erased. You should strive to ensure that you don't keep unnecessary
references to your `Totp` instances.

### Notifying users

There are three common ways that users are provided with the details of their TOTP secret and most authenticator apps
support at least one of them - many support all three. Whichever way you choose to distribute secrets you should impress
upon users that they should either not store it or ensure it is stored securely.

**1. Sending just the secret**

The first is simply sending them the secret. Since the secret is a binary string, it will need to be converted to some
kind of plain-text safe format, and Base32 is usually used for this. This method of notifying users is only viable if
the standard TOTP setup is being used - that is 6-digit OTPs, SHA1 hashes, the Unix epoch as the reference time and 30
seconds as the time step. If you are using a custom TOTP setup, you will need to provide more information to your users,
and they will need to perform more steps to configure their authenticator app.

```php
$user->notify(Base32::encode(decrypt($user->totpSecret)));
```

**2. Sending an `otpauth` URL**

The second method is to send your users a specially constructed URL that their authenticator app can read. The URL
format is [described here](https://github.com/google/google-authenticator/wiki/Key-Uri-Format). _php-totp_ provides a
`UrlGenerator` class to create these URLs:

```php
$user->notify(UrlGenerator::from("MyWebApp")->for($user->username)->urlFor(new Totp(decrypt($user->totpSecret)));
```

By default, the UrlGenerator will insert as much information into the generated URL as is necessary to represent your
TOTP setup. So if you are using the SHA512 hash algorithm, the generated URL will contain the `algorithm` URL parameter
but if you're using the default SHA1 algorithm, the `algorithm` URL parameter will be omitted. The `UrlGenerator` class
provides a fluent interface to configure how it constructs the URLs (for example, you can force it to generate the
`algorithm` URL parameter regardless of whether you are using a non-default algorithm by chaining the `withAlgorithm()`
method before the `urlFor()` method).

This method of notifying supports all custom setups except those that use a non-standard reference time (since there is
no URL parameter for specifying it). Many TOTP-capable authenticator apps support URLs of this type, although you will
need to check the level of support in the app you are targeting for your users - for example _Google Authenticator_
supports URLs but does not recognise the `algorithm` parameter and always uses the SHA1 algorithm.

**3. Sending a QR code**

The third method is to send users a QR code that their authenticator app can scan. This is effectively identical to
using the URL method above - the QR code is simply a representation of the generated URL.

_php-totp_ does not (yet) have a QR code generator, but it should be simple to use an existing QR code generator along
with the `UrlGenerator` to create QR codes to send to your users.
[_bacon/bacon-qr-code_](https://packagist.org/packages/bacon/bacon-qr-code) is one such external library.

### Verifying successful provisioning

Once a user has been provisioned, you need to aks them them for the OTP from their authenticator app to confirm that it
has been set up successfully. Once you've received the user's input, verification is simple:

```php
$isVerified = (new Totp(decrypt($user->totpSecret))->verify($inputOtp);
```

To avoid problems that can arise when the user enters their OTP close to the end of a time step, you can choose to
accept a certain number of previous passwords as well as the current password. You can do this by providing a `window`
argument to the `Totp::verify()` method. The argument identifies the maximum number of time steps the verification will
go back to check for a matching OTP.

```php
$isVerified = (new Totp(decrypt($user->totpSecret))->verify(password: $inputOtp, window: 1);
```

By default, `Totp::verify()` only accepts the current OTP. **It is very strongly recommended that you verify _at
most_ with a window of 1 (i.e. accept either the current OTP or the one immediately preceding it).**

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

The specification mandates that each generated OTP must be used only once to successfully authenticate. That is, once an
OTP has been used to successfully authenticate, that OTP may not be used again.

One way to ensure each OTP is never reused is to record the TOTP counter after each successful authentication. The
counter is an incrementing integer that indicates how many time steps have passed since the reference time. By recording
the highest used counter value and refusing verification of any OTP generated at or before the corresponding time step
you can ensure that no OTP can be reused.

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

It is important that you ensure that **all routes to authentication that use the TOTP secret are protected in this
way** - for example if you have a mobile app and a web app, you must ensure that a OTP used to authenticate with the web
app cannot subsequently be used to authenticate using the mobile app. [RFC 4226](https://www.ietf.org/rfc/rfc4226.txt)
has a good discussion of the reasoning for this.

## Custom TOTP configurations

There are four things you can customise about your TOTP setup:

1. The hashing algorithm
2. The reference timestamp
3. The size of the time step
4. The number of digits in your OTPs

Customising your TOTP setup should be considered a one-time option. Once you have settled on a setup it is difficult
to change it (you'd need to re-provision all your users and they would all need to reconfigure their authenticator apps)
so it's usually best to choose your setup carefully before you begin.

Both the `Totp` constructor and the convenience factory methods `Totp::sixDigits()`, `Totp::eightDigits()` and
`Totp::integer()` accept arguments to customise all four aspects of TOTP. All these arguments use the defaults specified
in the TOTP RFC unless you explicitly provide a value, which means you can use PHP's named arguments to customise only
those aspects of your TOTP instances that are non-default.

### Hashing algorithms

TOTP supports three hashing algorithms - SHA1, SHA256 and SHA512. The strongest is SHA512, while the default specified
in the RFC is SHA1 (for compatibility with HOTP). As noted above, you should check that the authenticator apps that you
are targeting for your users support the algorithm you are intending to use before customising it.

The `Totp` class provides constants representing all supported hashing algorithms, and you are strongly encouraged to
use these to avoid exceptions in your app. Using the constants protects your code against changes to the underlying
values that are used to represent the algorithms, and will provide you with a pain-free upgrade path for your app
if/when _php-totp_ is updated to use a PHP8.1 enumeration for specifying hash algorithms.

To use SHA256 create your `Totp` instances like this:

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

The counter that TOTP uses is the number of time steps that have elapsed since the reference time. By default, the
reference time is 00:00:00 01/01/1970 (AKA the Unix epoch, or the Unix timestamp `0`). The default time step size is 30
seconds. Unless you have a good reason to deviate from them, these defaults are reasonable choices. If you do choose to
customise the time step, bear in mind that very small intervals will make it harder for users since they'll have less
time available to enter the correct OTP. Similarly, making the interval too large can also make it difficult for users
since you may effectively lock them out for a short period after they log off.

To use a time step of 60 seconds instead of 30 create your `Totp` instances like this:

```php
// when provisioning
$totp = new Totp(timeStep: 60);
// when verifying
$totp = new Totp(secret: decrypt($user->totpSecret), timeStep: 60);
```

You can customise the reference time using either Unix timestamps:

```php
// when provisioning
$totp = new Totp(referenceTime: 86400);
// when verifying
$totp = new Totp(secret: decrypt($user->totpSecret), referenceTime: 86400);
```

or DateTime objects:

```php
// when provisioning
$totp = new Totp(referenceTime: new DateTime("1970-01-02 00:00:00", new DateTimeZone("UTC")));
// when verifying
$totp = new Totp(secret: decrypt($user->totpSecret), referenceTime: new DateTime("1970-01-02 00:00:00", new DateTimeZone("UTC")));
```

Both of these examples create a TOTP with the reference time set to midnight on January 2nd 1970 UTC. You are strongly
encouraged to use the UTC timezone when creating `DateTime` objects to avoid any confusion. The TOTP algorithm works
with Unix timestamps that are always measured from 00:00:00, 01/01/9170 UTC.

You can customise both the time step and reference time:

```php
// when provisioning
$totp = new Totp(timeStep: 60, referenceTime: new DateTime("1970-01-02 00:00:00", new DateTimeZone("UTC")));
// when verifying
$totp = new Totp(secret: decrypt($user->totpSecret), timeStep: 60, referenceTime: new DateTime("1970-01-02 00:00:00", new DateTimeZone("UTC")));
```

And also the hash algorithm:

```php
// when provisioning
$totp = new Totp(
    timeStep: 60,
    referenceTime: new DateTime("1970-01-02 00:00:00", new DateTimeZone("UTC")),
    hashAlgorithm: Totp::Sha512Algorithm
);

// when verifying
$totp = new Totp(
    secret: decrypt($user->totpSecret),
    timeStep: 60,
    referenceTime: new DateTime("1970-01-02 00:00:00", new DateTimeZone("UTC")),
    hashAlgorithm: Totp::Sha512Algorithm
);
```

### Password digits

The number of digits in your OTPs defaults to 6, but can range from 6 to 9 inclusive. There's technically no reason why
larger numbers of digits can't be used, but owing to the internal mechanism by which the password is generated there is
nothing to gain since the number from which it is derived has at most 9 digits, so any more digits will just result in
padding with 0s to the left.

The easiest way to create a `Totp` with 8 digits is to use the `Totp::eightDigits()`convenience factory method:

```php
// when provisioning
$totp = Totp::eightDigits();
// when verifying
$totp = Totp::eightDigits(decrypt($user->totpSecret));
```

You can, of course, still customise other aspects of your `Totp`:

```php
// when provisioning
$totp = Totp::eightDigits(
    timeStep: 60,
    referenceTime: new DateTime("1970-01-02 00:00:00", new DateTimeZone("UTC")),
    hashAlgorithm: Totp::Sha512Algorithm
);

// when verifying
$totp = Totp::eightDigits(
    secret: decrypt($user->totpSecret),
    timeStep: 60,
    referenceTime: new DateTime("1970-01-02 00:00:00", new DateTimeZone("UTC")),
    hashAlgorithm: Totp::Sha512Algorithm
);
```

If you want to use a less common number of digits, use the `Totp::integer()` method:

```php
// when provisioning
$totp = Totp::integer(9);
// when verifying
$totp = Totp::integer(digits: 9, secret: decrypt($user->totpSecret));
```

And again, with more customisation:

```php
// when provisioning
$totp = Totp::integer(
    digits: 9,
    timeStep: 60,
    referenceTime: new DateTime("1970-01-02 00:00:00", new DateTimeZone("UTC")),
    hashAlgorithm: Totp::Sha512Algorithm
);

// when verifying
$totp = Totp::integer(
    digits: 9,
    secret: decrypt($user->totpSecret),
    timeStep: 60,
    referenceTime: new DateTime("1970-01-02 00:00:00", new DateTimeZone("UTC")),
    hashAlgorithm: Totp::Sha512Algorithm
);
```

For control over passwords that is more than just the number of digits they contain, you can provide the `renderer`
argument to the constructor. For example, to have your `Totp` produce 5-character OTPs that are compatible with the
_Steam_ authenticator:

```php
// when provisioning
$totp = new Totp(renderer: new Steam());
// when verifying
$totp = new Totp(secret: decrypt($user->totpSecret), renderer: new Steam());
```

And with more customised aspects:

```php
// when provisioning
$totp = new Totp(
    renderer: new Steam(),
    timeStep: 60,
    referenceTime: new DateTime("1970-01-02 00:00:00", new DateTimeZone("UTC")),
    hashAlgorithm: Totp::Sha512Algorithm
);

// when verifying
$totp = new Totp(
    renderer: new Steam(),
    secret: decrypt($user->totpSecret),
    timeStep: 60,
    referenceTime: new DateTime("1970-01-02 00:00:00", new DateTimeZone("UTC")),
    hashAlgorithm: Totp::Sha512Algorithm
);
```

## Base{32|64} secrets

As mentioned above, TOTP is commonly used with secrets that are encoded either as Base32 or Base64 plain text to make
them easy to enter into authenticator apps. If you have your secrets stored using one of these encodings (for example
in a text field in your database), they will need decoding (as well as decrypting) before being passed to a `Totp`
instance.

You can either do this yourself:

```php
$totp = new Totp(Base32::decode(decrypt($user->totpSecret)));
```

Or you can use the `TotpSecret` utility class:

```php
$totp = new Totp(TotpSecret::fromBase32(decrypt($user->totpSecret)));
```

### Provisioning multiple users

Provision multiple users with TOTP and send each a notification with a URL they can import into their authenticator app.

````php
$generator = UrlGenerator::from("Equit");

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
$totp = Totp::sixDigits(secret: $user->totpSecret());

if ($totp->verify(password: $_POST["totp"], window: 1)) {
    // user is authenticated
} else {
    // user is not authenticated
}

$totp->setSecret(random_bytes(20));
$totp = null;
````

## Generating your own secure secrets

As mentioned above, `Totp` provides a method for generating secrets that are as cryptographically strong as is possible
for all valid hash algorithms supported by TOTP. However, if you can't or don't want to use this method, this section
describes how to generate strong secrets.

The TOTP specification mandates that secrets are generated randomly (i.e. not chosen by the user). So to generate good
secrets for your users you need a good source of random data. PHP's `random_bytes()` function is a suitable source. If
this is not available on your platform you'll need to look elsewhere. PHP's other random number generation functions are
not necessarily good sources of cryptographically secure randomness.

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
on HOTP, and HOTP uses HMACs, and HMACs reduce any key longer than the digest produced by the hashing algorithm to the
length of the digest by hashing it, there is little value in providing a secret longer than the digest size of the
algorithm in use. HOTP recommends 160 bits on the basis that the SHA1 algorithm's digests are of that length; if you are
using SHA256 or SHA512 algorithms with your TOTPs, that recommendation should probably increase to the length of their
digests - 256 bits (32 bytes) for SHA256 and 512 bits (64 bytes) for SHA512. Therefore, if you are providing your own
random secrets, the following would be good ways to generate them:

| Algorithm | Random secret generator |
|-----------|-------------------------|
| SHA1      | `random_bytes(20)`      |
| SHA256    | `random_bytes(32)`      |
| SHA512    | `random_bytes(64)`      |

## References
- H. Krawczyk, M. Bellare & R. Canetti, _[RFC2104: HMAC: Keyed-Hashing for Message Authentication](https://www.ietf.org/rfc/rfc2104.txt)_, https://www.ietf.org/rfc/rfc2104.txt, retrieved 17th April, 2022.
- D. M'Raihi, M. Bellare, F. Hoornaert, D. Naccache & O. Ranen, 2005, _[RFC4226: HOTP: An HMAC-Based One-Time Password Algorithm](https://www.ietf.org/rfc/rfc4226.txt)_, https://www.ietf.org/rfc/rfc4226.txt, retrieved 17th April, 2022.
- D. M'Raihi, S. Machani, M. Pei & J. Rydell, 2011, _[RFC6238: TOTP: Time-Based One-Time Password Algorithm](https://www.ietf.org/rfc/rfc6238.txt)_, https://www.ietf.org/rfc/rfc6238.txt, retrieved 17th April, 2022.