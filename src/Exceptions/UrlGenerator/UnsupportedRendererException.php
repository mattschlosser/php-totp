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

namespace Equit\Totp\Exceptions\UrlGenerator;

use Equit\Totp\Contracts\Renderer;
use Throwable;

/**
 * Exception thrown when an UrlGenerator encounters a Renderer it can't work with.
 *
 * When the digits URL parameter is configured always to be included the renderer must be an instance of IntegerRenderer
 * in order to be able to determine the value for the parameter.
 */
class UnsupportedRendererException extends UrlGeneratorException
{
    /**
     * @var Renderer The unsupported renderer.
     */
    private Renderer $m_renderer;

    /**
     * @param \Equit\Totp\Contracts\Renderer $renderer The unsupported renderer.
     * @param string $message An optional description of why it's unsuported. Defaults to an empty string.
     * @param int $code An optional error code. Defaults to 0.
     * @param Throwable|null $previous An optional previous Throwable. Defaults to null.
     */
    public function __construct(Renderer $renderer, string $message = "", int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
        $this->m_renderer = $renderer;
    }

    /**
     * Fetch the unsupported renderer.
     *
     * @return \Equit\Totp\Contracts\Renderer The unsupported renderer.
     */
    public function getRenderer(): Renderer
    {
        return $this->m_renderer;
    }

    /**
     * Convenience method to get the class name of the unsupported renderer.
     *
     * @return string The renderer class name.
     */
    public function getRendererClass(): string
    {
        return get_class($this->getRenderer());
    }
}
