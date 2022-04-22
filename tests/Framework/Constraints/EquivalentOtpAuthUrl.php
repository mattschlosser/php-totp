<?php

declare(strict_types=1);

namespace Equit\Totp\Tests\Framework\Constraints;

use Equit\Totp\Tests\Framework\Exceptions\InvalidOtpUrlException;
use PHPUnit\Framework\Constraint\Constraint;
use RuntimeException;

class EquivalentOtpAuthUrl extends Constraint
{
    private const ValidationRegex = "/otpauth:\\/\\/(totp|hotp)\\/(?:([^\\/]+):)?([^\\/]+)(?:\\/\\?(.*))?/";
    private string $m_referenceUrl;
    private string $m_referenceOtpType;
    private string $m_referenceIssuer;
    private string $m_referenceUser;
    private array $m_referenceParameters;

    /**
     * @param string $referenceUrl
     *
     * @throws \Equit\Totp\Tests\Framework\Exceptions\InvalidOtpUrlException
     */
    public function __construct(string $referenceUrl)
    {
        if (!preg_match(self::ValidationRegex, $referenceUrl, $parts)) {
            throw new InvalidOtpUrlException($referenceUrl, "The reference URL is not valid.");
        }

        $this->m_referenceUrl = $referenceUrl;
        [$void, $this->m_referenceOtpType, $this->m_referenceIssuer, $this->m_referenceUser, $params,] = $parts;

        // NOTE the type is always either "totp" or "hotp" so it doesn't need decoding
        $this->m_referenceIssuer = urldecode($this->m_referenceIssuer);
        $this->m_referenceUser = urldecode($this->m_referenceUser);

        // NOTE we don't need to extract the key/value of each parameter, it's sufficient to check that the full
        // parameter string including its name has a match in the tested URL
        $this->m_referenceParameters = explode("&", $params);
        array_walk($this->m_referenceParameters, [self::class, "urlDecodeParameter",]);
    }

    private static function urlDecodeParameter(string & $value, string $key): void
    {
        $value = urldecode($value);
    }

    public function referenceUrl(): string
    {
        return $this->m_referenceUrl;
    }

    /**
     * @inheritDoc
     */
    public function toString(): string
    {
        return "is an URL equivalent to {$this->referenceUrl()}";
    }

    protected function matches(mixed $url): bool
    {
        if (!is_string($url)) {
            return false;
        }

        if (!preg_match(self::ValidationRegex, $url, $parts)) {
            return false;
        }

        try {
            [$void, $otpType, $issuer, $user, $params,] = $parts;
        } catch (RuntimeException $err) {
            return false;
        }

        $params = explode("&", $params);

        if (count($params) !== count($this->m_referenceParameters) ||
            $otpType !== $this->m_referenceOtpType ||       // this is always "totp" or "hotp", never needs url encoding
            urldecode($issuer) !== $this->m_referenceIssuer ||
            urldecode($user) !== $this->m_referenceUser) {
            return false;
        }

        array_walk($params, [self::class, "urlDecodeParameter",]);

        // check that the provided URL contains each of the required parameters
        foreach ($this->m_referenceParameters as $referenceParameter) {
            if (!in_array($referenceParameter, $params)) {
                return false;
            }
        }

        return true;
    }
}
