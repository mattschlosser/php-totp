<?php

namespace Equit\Totp\Renderers;

/**
 * Render a TOTP of six decimal digits.
 */
class SixDigits implements IntegerRenderer
{
	use RendersStandardIntegerPasswords;
	protected int $digitCount = 6;
}