<?php

declare(strict_types=1);

namespace Equit\Totp\Types;

use DateInterval;
use Equit\Totp\Exceptions\InvalidTimeStepException;
use Stringable;

final class TimeStep implements Stringable
{
    /** The default update time step for passwords. */
    public const DefaultTimeStep = 30;

    /** @var int The time step in seconds. */
    private int $seconds;

    /** @throws InvalidTimeStepException */
    public function __construct(int $seconds)
    {
        if (1 > $seconds) {
            throw new InvalidTimeStepException($seconds, "Expected valid TOTP time step, found {$seconds}.");
        }

        $this->seconds = $seconds;
    }

    /** @return int The length of the time step, in seconds. */
    public function seconds(): int
    {
        return $this->seconds;
    }

    /**
     * @api
     * @throws InvalidTimeStepException
     */
    public function fromSeconds(int $seconds): self
    {
        return new self($seconds);
    }

    /**
     * @api
     * @throws InvalidTimeStepException
     */
    public function fromMinutes(int $minutes): self
    {
        return new self($minutes * 60);
    }

    /**
     * @api
     * @param DateInterval $interval
     * @return self
     * @throws InvalidTimeStepException
     */
    public function fromDateInterval(DateInterval $interval): self
    {
        if (0 !== $interval->y || 0 !== $interval->m) {
            throw new InvalidTimeStepException(0, "DateIntervals that include years or months cannot be used as they don't represent a fixed time interval.");
        }

        return new self(
            ($interval->d * 24 * 60 * 60)
            + ($interval->h * 60 * 60)
            + ($interval->m * 60)
            + $interval->s);
    }

    /** @return string The number of seconds, as a string. */
    public function __toString(): string
    {
        return (string) $this->seconds;
    }
}
