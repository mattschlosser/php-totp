# Command-line tools

The scripts in this directory are intended for use from the command-line. There are two files that are not commands
themselves and should not be executed directly:

- `bootstrap.php` bootstraps all the other commands
- `helpers.php` provides helper functions used by other commands

## Commands

### `totp.php`

Output the TOTP for a given configuration. This is a little like a lite version of
[`oathtool`](https://www.nongnu.org/oath-toolkit/). You can use it from the command-line to get the OTPs for your
services when logging in by providing it with your secret on the command-line. See the output of `totp.php --help` for
details on usage.
