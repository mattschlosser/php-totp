<?php

namespace Equit\Totp\Renderers;

/**
 * Interface for renderers that produce a fixed-width integer one-time password.
 */
interface IntegerRenderer extends Renderer
{
	/**
	 * @return int The number of digits to render.
	 */
	public function digits(): int;
}