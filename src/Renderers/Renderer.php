<?php

namespace Equit\Totp\Renderers;

/**
 * Interface for renderers that turn TOTP HMACs into the actual one-time passwords required.
 */
interface Renderer
{
	/**
	 * Produce the one-time password for an HMAC.
	 *
	 * @param string $hmac The HMAC to process.
	 *
	 * @return string The one-time password.
	 */
	public function render(string $hmac): string;
}