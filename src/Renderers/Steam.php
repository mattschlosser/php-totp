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

namespace Equit\Totp\Renderers;

use Equit\Totp\Contracts\Renderer;
use Equit\Totp\Renderers\Traits\ExtractsStandard31BitInteger;

/**
 * Renderer for Steam authenticator passwords.
 *
 * @warning This is only a tentative implementation, I have not been able to confirm that this is the correct algorithm.
 */
class Steam implements Renderer
{
    use ExtractsStandard31BitInteger;

	/** The Steam authenticator alphabet. */
	public const ValidCharacters = "23456789BCDFGHJKMNPQRTVWXY";

	/** The number of characters in the rendered passwords. */
	protected const CharacterCount = 5;

    /** @return string "Steam" */
    public function name(): string
    {
        return "Steam";
    }

	public function render(string $hmac): string
	{
        $passwordValue = self::extractIntegerFromHmac($hmac);
        $password      = "";

        // algorithm ported from PIP package steam-totp (https://pypi.org/project/steam-totp/)
		for ($i = 0; $i < self::CharacterCount; ++$i) {
			$password .= self::ValidCharacters[$passwordValue % strlen(self::ValidCharacters)];
			$passwordValue = (int) ($passwordValue / strlen(self::ValidCharacters));
		}

		return $password;
	}
}
