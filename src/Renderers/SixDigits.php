<?php

namespace Equit\Totp\Renderers;

use Equit\Totp\Renderer;

/**
 * Render a TOTP of six decimal digits.
 */
class SixDigits implements Renderer
{
	use RendersIntegerPasswords;
	protected int $digitCount = 6;
}