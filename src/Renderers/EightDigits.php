<?php

namespace Equit\Totp\Renderers;

/**
 * Render a TOTP of eight decimal digits.
 */
class EightDigits implements IntegerRenderer
{
	use RendersIntegerPasswords;
	protected int $digitCount = 8;
}