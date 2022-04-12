<?php

/*
 * Copyright 2022 Darren Edale
 *
 * This file is part of the php-totp package.
 *
 * php-totp is free software: you can redistribute it and/or modify
 * it under the terms of the Apache License v2.0.
 *
 * php-totp is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * Apache License for more details.
 *
 * You should have received a copy of the Apache License v2.0
 * along with php-totp. If not, see <http://www.apache.org/licenses/>.
 */

namespace Equit\Totp;

use Equit\Totp\Exceptions\InvalidBase32DataException;
use Equit\Totp\Exceptions\InvalidBase64DataException;
use Equit\Totp\Exceptions\InvalidTotpIntervalException;
use DateTime;
use DateTimeZone;

/**
 * Abstract base class for generating TOTP codes.
 */
abstract class Totp
{
    /**
     * The default update interval for codes.
     */
    public const DefaultInterval = 30;

    /**
     * The default baseline time for codes.
     */
    public const DefaultBaselineTime = 0;

    /**
     * The hashing algorithm to use when generating HMACs.
     */
    protected const HashAlgorithm = "sha1";

    /**
     * @var string|null The secret for the code.
     */
    private ?string $m_secret;

    /**
     * @var int The interval, in seconds, at which the code changes.
     */
    private int $m_interval;

    /**
     * @var int The baseline time against which codes are generated.
     */
    private int $m_baselineTime;

    /**
     * Initialise a new TOTP.
     *
     * If the baseline is specified as an int, it is interpreted as the number of seconds since the Unix epoch.
     *
     * @param string $secret The secret for the code. This must be the binary representation of the secret.
     * @param int $interval The update interval for the code. Defaults to 30 seconds.
     * @param int|\DateTime $baseline The baseline time from which the code is generated.
     * Defaults to 0.
     *
     * @throws InvalidTotpIntervalException if the interval is not a positive integer.
     */
    public function __construct(string $secret, int $interval = self::DefaultInterval, int | DateTime $baseline = self::DefaultBaselineTime)
    {
        $this->setSecret($secret);
        $this->setInterval($interval);
        $this->m_baselineTime = $baseline;
    }

    /**
     * Check whether a secret has been set.
     *
     * @return bool
     */
    public function hasSecret(): bool
    {
        return isset($this->m_secret);
    }

    /**
     * Fetch the raw secret.
     *
     * The raw secret is a byte sequence, not technically a string. It is likely to contain non-printable bytes.
     *
     * @return string The raw secret.
     */
    public function secret(): string
    {
        return $this->m_secret;
    }

    /**
     * @return string The secret, base32 encoded so that it's printable.
     */
    public function base32Secret(): string
    {
        return Base32::encode($this->secret());
    }

    /**
     * @return string The secret, base64 encoded so that it's printable.
     */
    public function base64Secret(): string
    {
        return Base64::encode($this->secret());
    }

    /**
     * Set the secret for generated codes.
     *
     * @param string $secret The binary secret.
     */
    public function setSecret(string $secret)
    {
        $this->m_secret = $secret;
    }

    /**
     * Set the secret for generated codes.
     *
     * The provided secret must be base32 encoded.
     *
     * @param string $secret
     *
     * @throws InvalidBase32DataException if the provided secret is not a valid base32 encoding.
     */
    public function setBase32Secret(string $secret)
    {
        $this->setSecret(Base32::decode($secret));
    }

    /**
     * Set the secret for generated codes.
     *
     * The provided secret must be base64 encoded.
     *
     * @param string $secret The binary secret, base64-encoded.
     *
     * @throws InvalidBase64DataException if the provided secret is not a valid base64 encoding.
     */
    public function setBase64Secret(string $secret)
    {
        $this->setSecret(Base64::decode($secret));
    }

    /**
     * Fetch the interval at which the TOTP code changes, in seconds.
     *
     * @return int The interval.
     */
    public function interval(): int
    {
        return $this->m_interval;
    }

    /**
     * @param int $interval
     *
     * @throws InvalidTotpIntervalException
     */
    public function setInterval(int $interval)
    {
        if (1 > $interval) {
            throw new InvalidTotpIntervalException($interval, "The interval for a TOTP must be >= 1 second.");
        }

        $this->m_interval = $interval;
    }

    /**
     * Fetch the baseline against which the TOTP codes will be generated.
     *
     * The baseline is returned as the number of seconds since the Unix epoch.
     *
     * @return int The baseline number of seconds.
     */
    public function baseline(): int
    {
        return $this->m_baselineTime;
    }

    /**
     * The baseline against which codes are generated as a DateTime object.
     *
     * @return \DateTime The baseline time.
     */
    public function baselineDateTime(): DateTime
    {
        return DateTime::createFromFormat("U", "{$this->m_baselineTime}", new DateTimeZone("UTC"));
    }

    /**
     * Set the baseline time against which OTP codes are generated.
     *
     * The baseline can be set either as an integer number of seconds since the Unix epoch or as a PHP DateTime object.
     * If using a DateTime object, make sure you know what time it represents in UTC since it is the number of seconds
     * since 1970-01-01 00:00:00 UTC that will be used as the baseline. (In effect, the DateTime you provide is
     * converted to UTC before the number of seconds is calculated.)
     *
     * @param int|\DateTime $baseline The
     *
     * @return void
     */
    public function setBaseline(int | DateTime $baseline)
    {
        if ($baseline instanceof DateTime) {
            $baseline = $baseline->getTimestamp();
        }

        $this->m_baselineTime = $baseline;
    }

    /**
     * Fetch the counter for the code at a given time.
     *
     * @param \DateTime|int $time The time at which the counter is sought.
     *
     * @return string The 64 bits of the counter, in BIG ENDIAN format.
     */
    protected function counterAt(DateTime | int $time): string
    {
        return pack("J", (int) floor((($time instanceof DateTime ? $time->getTimestamp() : $time) - $this->baseline()) / $this->interval()));
    }

    /**
     * Fetch the current counter for the code.
     *
     * @return string The 64 bits of the counter, in BIG ENDIAN format.
     * @noinspection PhpDocMissingThrowsInspection DateTime() constructor will not throw.
     */
    protected function counter(): string
    {
        /** @noinspection PhpUnhandledExceptionInspection DateTime constructor guaranteed not to throw here */
        return $this->counterAt(new DateTime("now", new DateTimeZone("UTC")));
    }

    /**
     * Fetch the raw TOTP HMAC at a given time.
     *
     * This is the raw byte sequence generated using the secret, baseline and interval.
     *
     * @param \DateTime|int $time The time at which the hmac is sought.
     *
     * @return string The current TOTP code.
     */
    public function hmacAt(DateTime | int $time): string
    {
        return self::hmac($this->secret(), $this->counterAt($time));
    }

    /**
     * Fetch the raw current TOTP HMAC.
     *
     * This is the raw byte sequence generated using the secret, baseline and interval.
     *
     * @return string The current TOTP code.
     */
    public function currentHmac(): string
    {
        return self::hmac($this->secret(), $this->counter());
    }

    /**
     * Fetch the TOTP password at a given point in time.
     *
     * Subclasses should reimplement this method to produce readable representations of the current raw code.
     * Commonly this is 6- or 8- decimal digits produced according to a defined algorithm that works with the raw
     * code.
     *
     * @param \DateTime|int $time The time at which the password is sought.
     *
     * @return string The current TOTP code, formatted for display.
     * @noinspection PhpDocMissingThrowsInspection DateTime constructor does not throw in this instance.
     */
    public abstract function passwordAt(DateTime | int $time): string;

    /**
     * Fetch the current TOTP password.
     *
     * The base implementation delegates to passwordAt().
     *
     * @return string The current TOTP password.
     * @noinspection PhpDocMissingThrowsInspection DateTime constructor does not throw in this instance.
     */
    public function currentPassword(): string
    {
        /** @noinspection PhpUnhandledExceptionInspection */
        return $this->passwordAt(new DateTime("now", new DateTimeZone("UTC")));
    }

    /**
     * Helper to generate the TOTP HMAC for a given key and message.
     *
     * The TOTP algorithm uses SHA1 as the hashing algorithm for HMACs.
     *
     * @param string $key The key.
     * @param string $message The message.
     *
     * @return string The HMAC for the key and message.
     */
    protected static function hmac(string $key, string $message): string
    {
        $blockSize = 64;

        if (strlen($key) > $blockSize) {
            $key = hash(self::HashAlgorithm, $key, true);
        } else if (strlen($key) < $blockSize) {
            $key = str_pad($key, $blockSize, "\x00");
        }

        $oKeyPad = str_repeat("\x5c", $blockSize);
        $iKeyPad = str_repeat("\x36", $blockSize);

        for ($i = 0; $i < $blockSize; ++$i) {
            $oKeyPad[$i] = chr(ord($oKeyPad[$i]) ^ ord($key[$i]));
            $iKeyPad[$i] = chr(ord($iKeyPad[$i]) ^ ord($key[$i]));
        }

        return hash(self::HashAlgorithm, $oKeyPad . hash(self::HashAlgorithm, $iKeyPad . $message, true), true);
    }
}
