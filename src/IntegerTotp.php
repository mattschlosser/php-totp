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

use Equit\Totp\Exceptions\InvalidTotpDigitsException;
use Equit\Totp\Exceptions\InvalidTotpIntervalException;
use DateTime;

/**
 * Base class for TOTP renderers that produce integers of fixed digit lengths.
 *
 * TOTPs are commonly rendered as either 6 or 8 0-padded digits. This base class implements the algorithm for
 * generating the output, subclasses just need to implement the static method digits() to indicate how many digits are
 * used in the rendering.
 */
class IntegerTotp extends Totp
{
    /**
     * @var int The number of digits in the generated TOTP passwords. Always >= 1.
     */
    private int $m_digits;

    /**
     * TOTP generator with passwords composed of a fixed number of numeric digits.
     *
     * @param int $digits The number of digits in the generated passwords.
     * @param string $secret The TOTP secret.
     * @param int $interval The generation interval.
     * @param \DateTime|int $baseline The baseline time.
     *
     * @throws InvalidTotpDigitsException
     * @throws InvalidTotpIntervalException
     */
    public function __construct(int $digits, string $secret, int $interval = self::DefaultInterval, DateTime | int $baseline = self::DefaultBaselineTime)
    {
        if (1 > $digits) {
            throw new InvalidTotpDigitsException($digits, "Number of digits must be >= 1.");
        }

        parent::__construct($secret, $interval, $baseline);
        $this->m_digits = $digits;
    }

    /**
     * @return int The number of digits in the generated TOTP password.
     */
    public function digits(): int
    {
        return $this->m_digits;
    }

	/**
     * Fetch the password at a given point in time.
     *
	 * @inheritDoc
	 */
	public function passwordAt(DateTime | int $time): string
	{
        $code = $this->hmacAt($time);
        $offset = ord($code[19]) & 0xf;

        // NOTE static:: here is guaranteed to refer to a non-abstract subclass - static::digits() WILL be implemented
        $code = (
                (ord($code[$offset]) & 0x7f) << 24
                | ord($code[$offset + 1]) << 16
                | ord($code[$offset + 2]) << 8
                | ord($code[$offset + 3])
            ) % (10 ** $this->digits());
        return str_pad("{$code}", 6, "0", STR_PAD_LEFT);
	}
}
