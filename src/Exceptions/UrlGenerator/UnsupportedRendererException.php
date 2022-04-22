<?php

namespace Equit\Totp\Exceptions\UrlGenerator;

use Equit\Totp\Renderers\Renderer;
use Throwable;

class UnsupportedRendererException extends UrlGeneratorException
{
	/**
	 * @var Renderer The invalid renderer.
	 */
	private Renderer $m_renderer;

	/**
	 * @param \Equit\Totp\Renderers\Renderer $renderer The invalid renderer.
	 * @param string $message An optional description of why it's invalid. Defaults to an empty string.
	 * @param int $code An optional error code. Defaults to 0.
	 * @param Throwable|null $previous An optional previous Throwable. Defaults to null.
	 */
	public function __construct(Renderer $renderer, string $message = "", int $code = 0, ?Throwable $previous = null)
	{
		parent::__construct($message, $code, $previous);
		$this->m_renderer = $renderer;
	}

	/**
	 * Fetch the invalid renderer.
	 *
	 * @return \Equit\Totp\Renderers\Renderer The invalid renderer.
	 */
	public function getRenderer(): Renderer
	{
		return $this->m_renderer;
	}

	/**
	 * Convenience method to get the class name of the invalid renderer.
	 *
	 * @return string The renderer class name.
	 */
	public function rendererClass(): string
	{
		return get_class($this->getRenderer());
	}
}