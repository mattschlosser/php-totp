<?php

declare(strict_types=1);

namespace Equit\Totp\Tests\Framework\Constraints;

use PHPUnit\Framework\Constraint\Constraint;

/**
 * Constraint that evaluates whether a string is composed entirely of characters drawn from another string.
 */
class StringContainsOnly extends Constraint
{
	/**
	 * @var string The characters that will be used to evaluate whether some argument meets the constraint.
	 */
	private string $m_characters;

	/**
	 * Initialise a new instance of the constraint.
	 *
	 * @param string $string The set of characters that must exclusively compose the tested string.
	 */
	public function __construct(string $string)
	{
		$this->m_characters = $string;
	}

	/**
	 * @return string The characters that will be used to evaluate whether some argument meets the constraint.
	 */
	public function characters(): string
	{
		return $this->m_characters;
	}

	/**
	 * @return string A string representation of the constraint.
	 */
	public function toString(): string
	{
		return "contains only characters in \"{$this->m_characters}\"";
	}

	/**
	 * Evaluates the constraint for a given argument
	 *
	 * @param mixed $other value or object to evaluate
	 *
	 * @eturn true if the constraint is met, false otherwise.
	 */
	protected function matches(mixed $other): bool
	{
		if ("" === $this->characters()) {
			return true;
		}

		return strlen($other) === strspn($other, $this->characters());
	}
}