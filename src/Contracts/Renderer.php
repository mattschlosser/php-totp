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

namespace Equit\Totp\Contracts;

/** Contract for renderers that turn TOTP HMACs into the actual one-time passwords required. */
interface Renderer
{
    /** The name of the rendering scheme used to turn the TOTP HMAC into a passcode. */
    public function name(): string;

    /**
     * Produce the one-time password for an HMAC.
     *
     * @param string $hmac The HMAC to process.
     *
     * @return string The one-time password.
     */
    public function render(string $hmac): string;
}
