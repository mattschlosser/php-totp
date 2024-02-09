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

namespace Equit\Totp\Tests\Exceptions\UrlGenerator;

use Equit\Totp\Contracts\Renderer;
use Equit\Totp\Exceptions\UrlGenerator\UnsupportedRendererException;
use Equit\Totp\Renderers\EightDigits;
use Equit\Totp\Renderers\Integer;
use Equit\Totp\Renderers\SixDigits;
use Equit\Totp\Tests\Framework\TestCase;
use Exception;
use TypeError;

/**
 * Unit test for the UnsupportedRendererException class.
 */
class UnsupportedRendererExceptionTest extends TestCase
{
    /**
     * Create an anonymous unsupported Renderer instance.
     *
     * @return \Equit\Totp\Contracts\Renderer The generated renderer.
     */
    private static function createUnsupportedRenderer(): Renderer
    {
        return new class implements Renderer
        {
            public function render(string $hmac): string
            {
                return "fizzbuzz";
            }
        };
    }

    /**
     * Test data for UnsupportedRendererException constructor.
     *
     * @return array The test data.
     */
    public function dataForTestConstructor(): array
    {
        return [
            "typicalRendererOnly" => [self::createUnsupportedRenderer(),],
            "typicalRendererAndMessage" => [self::createUnsupportedRenderer(), "This is not a supported renderer.",],
            "typicalRendererMessageAndCode" => [self::createUnsupportedRenderer(), "This is not a supported renderer.", 12,],
            "typicalRendererMessageCodeAndPrevious" => [self::createUnsupportedRenderer(), "This is not a supported renderer.", 12, new Exception("foo"),],
            "invalidStringRenderer" => [Integer::class, "class-string is not a supported renderer.", 12, new Exception("foo"), TypeError::class],
            "invalidNullRenderer" => [null, "null is not a supported renderer.", 12, new Exception("foo"), TypeError::class],
            "invalidStringableRenderer" => [self::createStringable(""), "'' is not a supported renderer.", 12, new Exception("foo"), TypeError::class],
            "invalidIntRenderer" => [1, "1 is not a supported renderer.", 12, new Exception("foo"), TypeError::class],
            "invalidFloatRenderer" => [1.115, "1.115 is not a supported renderer.", 12, new Exception("foo"), TypeError::class],
            "invalidTrueRenderer" => [true, "true is not a supported renderer.", 12, new Exception("foo"), TypeError::class],
            "invalidFalseRenderer" => [false, "false is not a supported renderer.", 12, new Exception("foo"), TypeError::class],
            "invalidArrayRenderer" => [["render" => fn(string $hmac): string => "",], "array is not a supported renderer.", 12, new Exception("foo"), TypeError::class],
            "invalidObjectRenderer" => [(object)["render" => fn(string $hmac): string => "",], "object is not a supported renderer.", 12, new Exception("foo"), TypeError::class],
        ];
    }

    /**
     * Test for UnsupportedRendererException constructor.
     *
     * @dataProvider dataForTestConstructor
     *
     * @param mixed $renderer The invalid Renderer instance for the test exception.
     * @param mixed $message The message for the test exception. Defaults to an empty string.
     * @param mixed $code The error code for the test exception. Defaults to 0.
     * @param mixed|null $previous The previous throwable for the test exception. Defaults to null.
     * @param string|null $exceptionClass The class name of the exception that is expected during the test, if any.
     */
    public function testConstructor(mixed $renderer, mixed $message = "", mixed $code = 0, mixed $previous = null, string $exceptionClass = null): void
    {
        if (isset($exceptionClass)) {
            $this->expectException($exceptionClass);
        }

        $exception = new UnsupportedRendererException($renderer, $message, $code, $previous);
        $this->assertSame($renderer, $exception->getRenderer(), "Unsupported Renderer retrieved from exception was not as expected.");
        $this->assertEquals($message, $exception->getMessage(), "Message retrieved from exception was not as expected.");
        $this->assertEquals($code, $exception->getCode(), "Error code retrieved from exception was not as expected.");
        $this->assertSame($previous, $exception->getPrevious(), "Previous throwable retrieved from exception was not as expected.");
    }

    /**
     * Test data for UnsupportedRendererException::getRenderer().
     *
     * @return array
     * @noinspection PhpDocMissingThrowsInspection Integer renderer constructor guaranteed not to throw here.
     */
    public function dataForTestGetRenderer(): array
    {
        /** @noinspection PhpUnhandledExceptionInspection Integer renderer constructor guaranteed not to throw here. */
        return [
            [new Integer(7),],
            [new SixDigits(),],
            [new EightDigits(),],
            [self::createUnsupportedRenderer(),],
        ];
    }

    /**
     * Test the UnsupportedRendererException::getRenderer() method.
     *
     * @dataProvider dataForTestGetRenderer
     *
     * @param Renderer $renderer The Renderer to test with.
     */
    public function testGetRenderer(Renderer $renderer): void
    {
        $exception = new UnsupportedRendererException($renderer);
        $this->assertSame($renderer, $exception->getRenderer(), "Unsupported renderer retrieved from exception was not as expected.");
    }

    /**
     * Test data for UnsupportedRendererException::getRendererClass().
     *
     * @return array The test data.
     * @noinspection PhpDocMissingThrowsInspection Integer renderer constructor guaranteed not to throw.
     */
    public function dataForTestGetRendererClass(): array
    {
        /** @noinspection PhpUnhandledExceptionInspection Renderer constructor guaranteed not to throw here */
        return [
            [new Integer(7), Integer::class,],
            [new SixDigits(), SixDigits::class,],
            [new EightDigits(), EightDigits::class,],
        ];
    }

    /**
     * Test the UnsupportedRendererException::getRendererClass() method.
     *
     * @dataProvider dataForTestGetRendererClass
     *
     * @param Renderer $renderer The Renderer to test with.
     * @param class-string $class The expected renderer class name.
     */
    public function testGetRendererClass(Renderer $renderer, string $class): void
    {
        $exception = new UnsupportedRendererException($renderer);
        $this->assertEquals($class, $exception->getRendererClass(), "Unsupported renderer class retrieved from exception was not as expected.");
    }
}
