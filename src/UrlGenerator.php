<?php

namespace Equit\Totp;

use BadMethodCallException;
use Equit\Totp\Exceptions\InvalidRendererException;
use Equit\Totp\Renderers\IntegerRenderer;

/**
 * Generate provisioning URLs for services that have OTP 2FA.
 *
 * Static fluent interface methods:
 *
 * @method self authenticatingWith(string $service): self
 * @method self for(string $user): self
 * @method self from(string $issuer): self
 */
class UrlGenerator
{
	/**
	 * The protocol for URLs.
	 *
	 * This is the only protocol for OTP provisioning URLs at the time of writing.
	 */
	public const Protocol = "otpauth";

	/**
	 * The authentication type.
	 *
	 * At the time of writing the options are "totp" and "hotp". Since this is a TOTP library, we only do "totp" (for
	 * now).
	 */
	public const AuthenticationType = "totp";

	/**
	 * @var string|null The issuer of the TOTP.
	 */
	private ?string $m_issuer;

	/**
	 * @var string The user being provisioned.
	 */
	private string $m_user = "";

	/**
	 * @var bool Whether the number of digits will be included in generated URLs.
	 */
	private bool $m_includeDigits = false;

	/**
	 * @var bool Whether the hash algorithm will be included in generated URLs.
	 */
	private bool $m_includeAlgorithm = false;

	/**
	 * @var bool Whether the period will be included in generated URLs.
	 */
	private bool $m_includePeriod = false;

	/**
	 * Determine whether an issuer has been set for the URL generator.
	 *
	 * @return bool true if an issuer has been set, false otherwise.
	 */
	public function hasIssuer(): bool
	{
		return isset($this->m_issuer);
	}

	/**
	 * Fetch the name of the issuer who is generating the provisioning URL.
	 *
	 * This can be null if no issuer is to appear in the generated provisioning URLs.
	 *
	 * @return string|null The issuer.
	 */
	public function issuer(): ?string
	{
		return $this->m_issuer;
	}

	/**
	 * Set the name of the issuer who is generating the provisioning URL.
	 *
	 * You can set this to null if you don't want a specific issuer to appear in the provisioning URL.
	 *
	 * The provided issuer will be URL encoded when the URL is generated, you don't need to (and shouldn't) do this
	 * yourself.
	 *
	 * @param string|null $issuer The issuer.
	 */
	public function setIssuer(string | null $issuer): void
	{
		$this->m_issuer = $issuer;
	}

	/**
	 * Set the name of the user for whom the provisioning URL is being generated.
	 *
	 * You can be null if a specific user name is not to appear in the provisioning URL, though this is not recommended
	 * as it means the user must label the TOTP in their app themselves.
	 *
	 * The provided user will be URL encoded when the URL is generated, you don't need to (and shouldn't) do this
	 * yourself.
	 *
	 * @return string $user The user.
	 */
	public function user(): string
	{
		return $this->m_user;
	}

	/**
	 * Set the name of the user for whom the provisioning URL is being generated.
	 *
	 * The provided user will be URL encoded when the URL is generated, you don't need to (and shouldn't) do this
	 * yourself.
	 *
	 * @param string $user The user.
	 */
	public function setUser(string $user): void
	{
		$this->m_user = $user;
	}

	/**
	 * The protocol part of the generated URL.
	 *
	 * The default is "otpauth", and you probably don't want to change this.
	 *
	 * @return string The protocol.
	 */
	public function protocol(): string
	{
		return self::Protocol;
	}

	/**
	 * Fetch the authentication type for the generated URL.
	 *
	 * The default is "totp". You can override this in subclasses if you want to use UrlGenerators for OTP
	 * authentication types other than TOTP.
	 *
	 * @return string The authentication type.
	 */
	public function authenticationType(): string
	{
		return self::AuthenticationType;
	}

	/**
	 * Fetch whether the period will be included in the provisioning URL.
	 *
	 * @return bool Whether the period will be included.
	 */
	public function includesPeriod(): bool
	{
		return $this->m_includePeriod;
	}

	/**
	 * Set whether the period should be included in the provisioning URL.
	 *
	 * @param bool $include Whether to include the period.
	 */
	public function setIncludePeriod(bool $include): void
	{
		$this->m_includePeriod = $include;
	}

	/**
	 * Fetch whether the number of digits will be included in the provisioning URL.
	 *
	 * @return bool Whether the digits will be included.
	 */
	public function includesDigits(): bool
	{
		return $this->m_includeDigits;
	}

	/**
	 * Set whether the number of digits should be included in the provisioning URL.
	 *
	 * Note that this will cause an exception to be thrown if any provided TOTP is not using a (subclass of) the Integer
	 * renderer.
	 *
	 * @param bool $include Whether to include the number of digits.
	 */
	public function setIncludeDigits(bool $include): void
	{
		$this->m_includeDigits = $include;
	}

	/**
	 * Fetch whether the hash algorithm will be included in the provisioning URL.
	 *
	 * @return bool Whether the algorithm will be included.
	 */
	public function includesAlgorithm(): bool
	{
		return $this->m_includeAlgorithm;
	}

	/**
	 * Set whether the hash algorithm should be included in the provisioning URL.
	 *
	 * @param bool $include Whether to include the algorithm.
	 */
	public function setIncludeAlgorithm(bool $include): void
	{
		$this->m_includeAlgorithm = $include;
	}

	/**
	 * Generate the provisioning URL for a given TOTP.
	 *
	 * @param Totp $totp The TOTP for which to generate the provisioning URL.
	 *
	 * @return string The URL.
	 * @throws \Equit\Totp\Exceptions\InvalidRendererException if the Totp's renderer is not an Integer renderer.
	 */
	public function urlFor(Totp $totp): string
	{
		$url = urlencode($this->protocol()) . "://" . urlencode($this->authenticationType()) . "/";

		if ($this->hasIssuer()) {
			$url .= urlencode($this->issuer()) . ":" . urlencode($this->user());
		} else {
			$url .= urlencode($this->user());
		}

		$url .= "?secret={$totp->base32Secret()}";

		if ($this->hasIssuer()) {
			$url .= "&issuer=" . urlencode($this->issuer());
		}

		if ($this->includesDigits()) {
			if (!($totp->renderer() instanceof IntegerRenderer)) {
				throw new InvalidRendererException($totp->renderer(), "The renderer must be an implementation of " . IntegerRenderer::class . " to include the digits in a generated URL.");
			}

			$url .= "&digits={$totp->renderer()->digits()}";
		}

		if ($this->includesAlgorithm()) {
			$url .= "&algorithm=" . strtoupper($totp->hashAlgorithm());
		}

		if ($this->includesPeriod()) {
			$url .= "&period={$totp->interval()}";
		}

		return $url;
	}

	/**
	 * Magic method to handle calls to non-existent methods.
	 *
	 * The UrlGenerator class provides a fluent interface that can be used statically. This magic method is required to
	 * enable URL generation to be done statically. It implements all the fluent methods for the class. The methods
	 * are documented in the class docs.
	 *
	 * @param string $method The method called.
	 * @param array $args The arguments provided in the call.
	 *
	 * @return $this
	 */
	public function __call(string $method, array $args): self
	{
		switch (strtolower($method)) {
			case "from":
				$this->setIssuer(...$args);
				return $this;

			case "for":
				$this->setUser(...$args);
				return $this;

			case "withperiod":
				$this->setIncludePeriod(true);
				return $this;

			case "withoutperiod":
				$this->setIncludePeriod(false);
				return $this;

			case "withdigits":
				$this->setIncludeDigits(true);
				return $this;

			case "withoutdigits":
				$this->setIncludeDigits(false);
				return $this;

			case "withalgorithm":
				$this->setIncludeAlgorithm(true);
				return $this;

			case "withoutalgorithm":
				$this->setIncludeAlgorithm(false);
				return $this;
		}

		throw new BadMethodCallException("Method {$method} is not defined.");
	}

	/**
	 * Magic method to enable the static fluent interface.
	 *
	 * Example (bulk provision some users):
	 *
	 *     $generator = UrlGenerator::authenticatingWith($service)->from($adminName);
	 *
	 * 	   foreach ($users as $user) {
	 *         $totp = Totp::sixDigitTotp(random_bytes(20));
	 *         $user->setTotpSecret(encrypt($totp->base32Secret()));
	 *         $user->sendTotpNotification($generator->for($user->userName())->urlFor($totp));
	 *     }
	 *
	 * Any subclasses you create must have a default constructor for the static fluent interface to work.
	 *
	 * @param string $method The method called.
	 * @param array $args The arguments provided in the call.
	 *
	 * @return static
	 */
	public static function __callStatic(string $method, array $args): static
	{
		return (new static())->__call($method, $args);
	}
}
