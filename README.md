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
