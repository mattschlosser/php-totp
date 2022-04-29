# API

This is an abridged summary of the parts of the API that you are most likely to use.

- [`Totp` class](API.md#totp)
- [`Base32` class](API.md#base32)
- [`Base64` class](API.md#base64)
- [`TotpSecret` class](API.md#totpsecret)
- [`UrlGenerator` class](API.md#urlgenerator)

## `Totp`

```php
__construct()
```

Create a new `Totp` instance configured according to the provided arguments (See the source for details).

Throws `InvalidSecretException` if the secret is given and is too short.
Throws `InvalidTimeStepException` if the time step is given and is < 1.
Throws `InvalidHashAlgorithmException` if the hash algorithm is given and is not one of the supported algorithms.

```php
static randomSecret(): string
```

Generate a cryptographically-secure random secret. The secret is guaranteed to be 512 bits (64 bytes) in length.

Throws `SecureRandomDataUnavailableException` if it can't find a source of cryptographically-secure random data.

```php
static sixDigits(): Totp
```

Create a six-digit `Totp`. All aspects other than the number of digits can be customised by providing arguments (see the
source for details). It is recommended you use named arguments to make customisation easier.

Throws `InvalidSecretException` if the secret is given and is too short.
Throws `InvalidTimeStepException` if the time step is given and is < 1.
Throws `InvalidHashAlgorithmException` if the hash algorithm is given and is not one of the supported algorithms.

```php
static eightDigits(): Totp
```

Create an eight-digit `Totp`. All aspects other than the number of digits can be customised by providing arguments (see
the source for details). It is recommended you use named arguments to make customisation easier.

Throws `InvalidSecretException` if the secret is given and is too short.
Throws `InvalidTimeStepException` if the time step is given and is < 1.
Throws `InvalidHashAlgorithmException` if the hash algorithm is given and is not one of the supported algorithms.

```php
static integer(int $digits): Totp
```

Create a `Totp` with a given number of digits in the passwords it generates. All aspects can be customised by providing
additional arguments (see the source for details). It is recommended you use named arguments to make customisation
easier.

Throws `InvalidSecretException` if the secret is given and is too short.
Throws `InvalidTimeStepException` if the time step is given and is < 1.
Throws `InvalidHashAlgorithmException` if the hash algorithm is given and is not one of the supported algorithms.

```php
hashAlgorithm(): string
```

The hash algorithm that the `Totp` uses.

```php
setHashAlgorithm(string $hashAlgorithm): void
```

Set the hash algorithm that the `Totp` uses. Throws an `InvalidHashAlgorithmException` if the given algorithm is not
valid.

```php
secret(): string
base32secret(): string
base64secret(): string
```

The unencoded/base32-encoded/base64-encoded `Totp` secret. Make sure you scrub the returned string as soon as you no
longer need it.

```php
setSecret(string | TotpSecret $secret): void
```

Set the secret for the `Totp`. A string must be the raw binary secret - if you need to set it from base32- or base64-
encoded text use `TotpSecret::fromBase32()`/`TotpSecret::fromBase64()`. Throws `InvalidSecretException` if the secret is
too short.

```php
timeStep(): int
```

The time step for the `Totp`.

```php
setTimeStep(int $timeStep): void
```

Set the time step for the `Totp`. Throws `InvalidTimeStepException` if the time step is < 1.

```php
referenceTimestamp(): int
referenceTime(): DateTime
```

The reference time for the `Totp` as a Unix timestamp/DateTime object. The returned DateTime is guaranteed to be in UTC.

```php
setReferenceTime(int | DateTime $referenceTime): void
```

Set the reference time for the `Totp`.

```php
counter(): int
counterAt(int | DateTime $time): int
```

The TOTP counter now/at a given point in time. The counter is the number of time steps that have passed between the
reference time and the current/given time.

Throws `InvalidTimeException` if the time at which to retrieve the counter is before the TOTP reference time.

```php
hmac(): string
hmacAt(int | DateTime $time): string
```

The HMAC now/at a given point in time. The secret is used as the key and the four bytes of the counter, in big endian
byte
order, are used as the message in the HMAC computation.

Throws `InvalidTimeException` if the time at which to retrieve the HMAC is before the TOTP reference time.

```php
password(): string
passwordAt(int | DateTime $time): string
```

The OTP now/at a given point in time.

Throws `InvalidTimeException` if the time at which to retrieve the OTP is before the TOTP reference time.

```php
verify(string $otp, ?int $window = 0): bool
verifyAt(string $opt, int | DateTime $time, ?int $window = 0): bool
```

Verify that a given OTP is identical to the correct OTP now/at a given point in time, optionally with a window of
validity.

Throws `InvalidTimeException` if the time at which to verify the OTP is before the TOTP reference time.

## `Base32`

```php
setEncoded(string $data): void
```

Set the base32-encoded content. Throws `InvalidBase32DataException` if the provided data is not valid base-32 text.

```php
encoded(): string
```

The base32-encoded content.

```php
setRaw(string $data): void
```

Set the raw content.

```php
raw(): string
```

The raw (i.e. base32-decoded) content.

```php
static encode(string $raw): string
```

Encode some raw data as base32 text.

```php
static decode(string $base32): string
```

Decode some base32 data to its raw bytes. Throws `InvalidBase32Exception` if the provided data is not valid base-32
text.

## `Base64`

```php
setEncoded(string $data): void
```

Set the base64-encoded content. Throws `InvalidBase64DataException` if the provided data is not valid base-64 text.

```php
encoded(): string
```

The base64-encoded content.

```php
setRaw(string $data): void
```

Set the raw content.

```php
raw(): string
```

The raw (i.e. base64-decoded) content.

```php
static encode(string $raw): string
```

Encode some raw data as base64 text.

```php
static decode(string $base64): string
```

Decode some base64 data to its raw bytes. Throws `InvalidBase64Exception` if the provided data is not valid base-64
text.

## `TotpSecret`

```php
raw(): string
```

The raw bytes of the secret.

```php
base32(): string
```

The base-32 encoded text for the secret.

```php
base64(): string
```

The base-64 encoded text for the secret.

```php
static fromRaw(string $rawSecret): TotpSecret
```

Create a `TotpSecret` object from the raw bytes of the secret.

```php
fromBase32(string $base32Secret): TotpSecret
```

Create a `TotpSecret` object from the base32-encoded text of the secret. Throws `InvalidBase32DataException` if the
provided data is not valid base-32 text.

```php
fromBase64(string $base64Secret): TotpSecret
```

Create a `TotpSecret` object from the base64-encoded text of the secret. Throws `InvalidBase64DataException` if the
provided data is not valid base-64 text.

## `UrlGenerator`