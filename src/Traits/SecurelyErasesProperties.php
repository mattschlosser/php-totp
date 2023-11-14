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

namespace Equit\Totp\Traits;

use ReflectionClass;
use function Equit\Totp\scrubString;

/**
 * Import this trait to have your class automatically scrub all string properties on destruction.
 */
trait SecurelyErasesProperties
{
    /**
     * Scrub all string properties by overwriting them with random data.
     */
    private function securelyEraseProperties(): void
    {
        foreach ((new ReflectionClass($this))->getProperties() as $property) {
            if (is_string($this->{$property->name})) {
                scrubString($this->{$property->name});
            }
        }
    }

    /**
     * Overwrite all string members on destruction.
     */
    public function __destruct()
    {
        $this->securelyEraseProperties();
    }
}
