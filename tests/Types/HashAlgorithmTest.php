<?php

declare(strict_types=1);

namespace Equit\Totp\Tests\Types;

use Equit\Totp\Exceptions\InvalidHashAlgorithmException;
use Equit\Totp\Tests\Framework\TestCase;
use Equit\Totp\Types\HashAlgorithm;

class HashAlgorithmTest extends TestCase
{
    private HashAlgorithm $hashAlgorithm;

    public function setUp(): void
    {
        $this->hashAlgorithm = new HashAlgorithm(HashAlgorithm::DefaultAlgorithm);
    }

    public function tearDown(): void
    {
        unset($this->hashAlgorithm);
    }

    public static function dataForTestConstructor1(): iterable
    {
        yield "sha1" => [HashAlgorithm::Sha1Algorithm];
        yield "sha256" => [HashAlgorithm::Sha256Algorithm];
        yield "sha512" => [HashAlgorithm::Sha512Algorithm];
    }

    /**
     * Ensure we can construct with valid algorithms.
     *
     * @dataProvider dataForTestConstructor1
     */
    public function testConstructor1(string $algorithm): void
    {
        $instance = new HashAlgorithm($algorithm);
        self::assertSame($algorithm, $instance->algorithm());
    }

    public static function dataForTestConstructor2(): iterable
    {
        yield "empty" => [""];
        yield "whitespace" => ["  "];
        yield "whitespace" => ["sha11"];
    }

    /**
     * Ensure the constructor throws with invalid algorithms.
     *
     * @dataProvider dataForTestConstructor2
     */
    public function testConstructor2(string $algorithm): void
    {
        self::expectException(InvalidHashAlgorithmException::class);
        self::expectExceptionMessage("Expected valid hash algorithm, found \"{$algorithm}\"");
        new HashAlgorithm($algorithm);
    }

    /** Ensure we can read the algorithm. */
    public function testAlgorithm1(): void
    {
        self::assertSame(HashAlgorithm::DefaultAlgorithm, $this->hashAlgorithm->algorithm());
    }

    public function testSha11(): void
    {
        self::assertSame(HashAlgorithm::Sha1Algorithm, HashAlgorithm::sha1()->algorithm());
    }

    public function testSha2561(): void
    {
        self::assertSame(HashAlgorithm::Sha256Algorithm, HashAlgorithm::sha256()->algorithm());
    }

    public function testSha5121(): void
    {
        self::assertSame(HashAlgorithm::Sha512Algorithm, HashAlgorithm::sha512()->algorithm());
    }

    public function testToString1(): void
    {
        self::assertSame(HashAlgorithm::DefaultAlgorithm, $this->hashAlgorithm->__toString());
    }
}
