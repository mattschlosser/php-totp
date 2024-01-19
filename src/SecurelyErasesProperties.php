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

declare(strict_types=1);

namespace Equit\Totp;

use ReflectionClass;

/**
 * Import this trait to have your class automatically scrub all string properties on destruction.
 *
 * This trait provides its importing class with a `securelyEraseProperties()` private method that uses reflection to
 * check for string properties and scrubs them using the `\Equit\Totp\scrubString()` function. This ensures that the
 * data they carried is not left lingering in the memory they were using once it is released. It also provides a simple
 * destructor that calls this method on destruction, ensuring that all the object's string properties are scrubbed when
 * the object is no longer in use.
 */
trait SecurelyErasesProperties
{
    /**
     * Scrub all string properties by overwriting them with random data.
     * @internal
     */
    private function securelyEraseProperties(): void
    {
        foreach ((new ReflectionClass($this))->getProperties() as $property) {
            if (!is_string($this->{$property->name})) {
                continue;
            }

            scrubString($this->{$property->name});
        }
    }

    /**
     * Scrub all string members on destruction.
     */
    public function __destruct()
    {
        $this->securelyEraseProperties();
    }
}
