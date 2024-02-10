<?php

declare(strict_types=1);

namespace Equit\TotpTests\Types;

use Equit\Totp\Exceptions\InvalidHashAlgorithmException;
use Equit\TotpTests\Framework\TestCase;
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
        yield "sha1" => [HashAlgorithm::Sha1Algorithm,];
        yield "sha256" => [HashAlgorithm::Sha256Algorithm,];
        yield "sha512" => [HashAlgorithm::Sha512Algorithm,];
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
        yield "empty" => ["",];
        yield "whitespace" => ["  ",];
        yield "almost-valid-algorithm" => ["sha11",];
        yield "valid-algorithm-prefixed-with-whitespace" => [" sha1",];
        yield "valid-algorithm-suffixed-with-whitespace" => ["sha1 ",];
        yield "valid-algorithm-surrounded-with-whitespace" => [" sha1 ",];
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

    /** Ensure we can get a Sha1 instance with the correct algorithm. */
    public function testSha11(): void
    {
        self::assertSame(HashAlgorithm::Sha1Algorithm, HashAlgorithm::sha1()->algorithm());
    }

    /** Ensure we can get a Sha256 instance with the correct algorithm. */
    public function testSha2561(): void
    {
        self::assertSame(HashAlgorithm::Sha256Algorithm, HashAlgorithm::sha256()->algorithm());
    }

    /** Ensure we can get a Sha512 instance with the correct algorithm. */
    public function testSha5121(): void
    {
        self::assertSame(HashAlgorithm::Sha512Algorithm, HashAlgorithm::sha512()->algorithm());
    }

    /** Ensure we get the algorithm when stringified. */
    public function testToString1(): void
    {
        self::assertSame(HashAlgorithm::DefaultAlgorithm, $this->hashAlgorithm->__toString());
    }
}
