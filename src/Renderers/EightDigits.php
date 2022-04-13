<?php

namespace Equit\Totp\Renderers;

use Equit\Totp\Renderer;

/**
 * Render a TOTP of eight decimal digits.
 */
class EightDigits implements Renderer
{
	use RendersIntegerPasswords;
	protected int $digitCount = 8;
}