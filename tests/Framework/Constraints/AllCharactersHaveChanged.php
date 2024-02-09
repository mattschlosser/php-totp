<?php
/*
 * Copyright 2024 Darren Edale
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

declare(strict_types=1);

namespace Equit\Totp\Tests\Framework\Constraints;

use PHPUnit\Framework\Constraint\Constraint;

/**
 * Constraint that evaluates whether a string's characters have all changed from its "before" state.
 *
 * Used to test the shredding of string data is effective at changing every character in it.
 */
class AllCharactersHaveChanged extends Constraint
{
    /**
     * @var string The string before it was shredded.
     */
    private string $m_before;

    /**
     * Initialise a new instance of the constraint.
     *
     * @param string $before The set of characters that must exclusively compose the tested string.
     */
    public function __construct(string $before)
    {
        $this->m_before = $before;
    }

    /**
     * @return string The characters that will be used to evaluate whether some argument meets the constraint.
     */
    public function before(): string
    {
        return $this->m_before;
    }

    /**
     * @return string A string representation of the constraint.
     */
    public function toString(): string
    {
        return "has had all characters changed";
    }

    /**
     * Evaluates the constraint for a given argument
     *
     * @param mixed $string value or object to evaluate
     *
     * @eturn true if the constraint is met, false otherwise.
     */
    protected function matches(mixed $string): bool
    {
        if (!is_string($string)) {
            return false;
        }

        $before = $this->before();
        $len    = strlen($before);

        if ($len !== strlen($string)) {
            return false;
        }

        for ($idx = 0; $idx < $len; ++$idx) {
            if ($before[$idx] === $string[$idx]) {
                return false;
            }
        }

        return true;
    }
}
